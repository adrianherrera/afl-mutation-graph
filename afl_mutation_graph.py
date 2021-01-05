#!/usr/bin/env python3

"""
Reconstructs an approximate AFL mutation graph based on the file names of seeds
in a queue.

Author: Adrian Herrera
"""


from argparse import ArgumentParser, Namespace
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple
import logging
import re
import sys

import networkx as nx
try:
    import pygraphviz
    from networkx.drawing.nx_agraph import write_dot
except ImportError:
    try:
        import pydot
        from networkx.drawing.nx_pydot import write_dot
    except ImportError:
        print('Neither pygraphviz or pydot were found')
        raise


# Regexs for extracting mutation information from seeds in the AFL queue
QUEUE_ORIG_SEED_RE = re.compile(r'id[:_](?P<id>\d+),(?:time[:_](?P<time>\d+),)?orig[:_](?P<orig_seed>\w+)')
QUEUE_MUTATE_SEED_RE = re.compile(r'id[:_](?P<id>\d+),(?:sig[:_](?P<sig>\d+),)?src[:_](?P<src>\d+),(?:time[:_](?P<time>\d+),)?op[:_](?P<op>(?!.*splice)\w+)(?:,pos[:_](?P<pos>\d+))?(?:,val[:_](?P<val_type>[\w:_]+)?(?P<val>[+-]\d+))?(?:,rep[:_](?P<rep>\d+))?')
QUEUE_MUTATE_SEED_SPLICE_RE = re.compile(r'id[:_](?P<id>\d+),(?:sig[:_](?P<sig>\d+),)?src[:_](?P<src_1>\d+)\+(?P<src_2>\d+),(?:time[:_](?P<time>\d+),)?op[:_](?P<op>.*splice),rep[:_](?P<rep>\d+)')
QUEUE_MUTATE_SEED_SYNC_RE = re.compile(r'id[:_](?P<id>\d+),sync[:_](?P<syncing_party>[\w-]+),src[:_](?P<src>\d+)')

# Maps short stag names to full stage names
OP_MAPPING = {
    'flip1': 'bitflip 1/1',
    'flip2': 'bitflip 2/1',
    'flip4': 'bitflip 4/1',
    'flip8': 'bitflip 8/8',
    'flip16': 'bitflip 16/8',
    'flip32': 'bitflip 32/8',
    'arith8': 'arith 8/8',
    'arith16': 'arith 16/8',
    'arith32': 'arith 32/8',
    'int8': 'interest 8/8',
    'int16': 'interest 16/8',
    'int32': 'interest 32/8',
    'ext_UO': 'user extras (over)',
    'ext_UI': 'user extras (insert)',
    'ext_AO': 'auto extras (over)',
    'havoc': 'havoc',
    'splice': 'splice',

    # AFL++ operators
    'colorization': 'colorization',
    'MOpt_core_havoc': 'MOpt core havoc',
    'MOpt_core_splice': 'MOpt core splice',
    'MOpt_havoc': 'MOpt havoc',
    'MOpt_splice': 'MOpt splice',
}

# Regex elements to convert to ints
CONVERT_TO_INTS = ('id', 'sig', 'src', 'src_1', 'src_2', 'pos', 'rep', 'val')

# Logging
FORMATTER = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger()


def parse_args() -> Namespace:
    """Parse command-line arguments."""
    def log_level(val: str) -> int:
        """Ensure that an argument value is a valid log level."""
        numeric_level = getattr(logging, val.upper(), None)
        if not isinstance(numeric_level, int):
            raise ArgumentTypeError('%r is not a valid log level' % val)
        return numeric_level

    parser = ArgumentParser(description='Recover (approximate) mutation graph'
                                        'from a set of AFL seeds')
    parser.add_argument('-s', '--stats', required=False, action='store_true',
                        help='Print statistics about the mutation graph')
    parser.add_argument('-o', '--output', required=False, metavar='DOT',
                        type=Path, help='Output path for DOT file')
    parser.add_argument('-l', '--log', default=logging.WARN, type=log_level,
                        help='Logging level')
    parser.add_argument('seed_path', nargs='+', metavar='SEED', type=Path,
                        help='Path to the seed(s) to recover mutation graph')
    return parser.parse_args()


def fix_regex_dict(mutation: dict) -> dict:
    """
    Fix the groupdict returned by the regex match.

    Convert strings to int, etc.
    """
    # Remove None values
    mutation = {k:v for k, v in mutation.items() if v is not None}

    # Convert ints
    for key in CONVERT_TO_INTS:
        if key in mutation:
            mutation[key] = int(mutation[key])

    # Expand op names to full stage names
    if 'op' in mutation:
        mutation['op'] = OP_MAPPING[mutation['op']]

    return mutation


def find_seed(seed_dir: Path, seed_id: int):
    """Find a seed file with the given ID."""
    seed_files = list(seed_dir.glob('id[:_]%06d,*' % seed_id))

    if not seed_files:
        raise Exception('Could not find seed %s in %s' % (seed_id, seed_dir))

    # Each seed should have a unique ID, so there should only be one result
    return seed_files[0]


def is_crash(mutation: dict) -> bool:
    """Returns `True` if the given mutation dict is for a crashing input."""
    return 'crashes' in mutation['path'].parent.name


def is_seed(mutation: dict) -> bool:
    """
    Returns `True` if the given mutation dict is for a seed from the fuzzing
    corpus.
    """
    return 'orig_seed' in mutation


def get_parent_seeds(mutation: dict) -> List[Path]:
    """Get a list of parent seeds from the given mutation dictionary."""
    seed_dir = mutation['path'].parent

    # If the seed is a crash, move across to the queue directory
    if is_crash(mutation):
        seed_dir = seed_dir.parent / 'queue'

    if 'orig_seed' in mutation:
        return []
    if 'syncing_party' in mutation:
        seed_dir = seed_dir.parents[1] / mutation['syncing_party'] / 'queue'
        return [find_seed(seed_dir, mutation['src'])]
    if 'src_1' in mutation:
        return [find_seed(seed_dir, mutation['src_1']),
                find_seed(seed_dir, mutation['src_2'])]
    if 'src' in mutation:
        return [find_seed(seed_dir, mutation['src'])]

    raise Exception('Invalid mutation dictionary %r' % mutation)


def get_mutation_dict(seed: Path) -> dict:
    """Parse out a mutation dict from the given seed."""
    # If the seed is a crash, move across to the queue directory
    seed_dir = seed.parent
    if seed_dir.name == 'crashes':
        seed_dir = seed_dir.parent / 'queue'

    seed_name = seed.name
    match = QUEUE_ORIG_SEED_RE.match(seed_name)
    if match:
        # We've reached the end of the chain
        mutation = fix_regex_dict(match.groupdict())
        mutation['path'] = seed

        return mutation

    match = QUEUE_MUTATE_SEED_RE.match(seed_name)
    if match:
        # Recurse on the parent 'src' seed
        mutation = fix_regex_dict(match.groupdict())
        mutation['path'] = seed

        return mutation

    match = QUEUE_MUTATE_SEED_SPLICE_RE.match(seed_name)
    if match:
        # Spliced seeds have two parents. Recurse on both
        mutation = fix_regex_dict(match.groupdict())
        mutation['path'] = seed

        return mutation

    match = QUEUE_MUTATE_SEED_SYNC_RE.match(seed_name)
    if match:
        # Seed synced from another fuzzer node
        mutation = fix_regex_dict(match.groupdict())
        mutation['path'] = seed

        return mutation

    raise Exception('Failed to find parent seed for `%s`' % seed_name)


def gen_mutation_graph(seed: Path) -> nx.DiGraph:
    """
    Generate a mutation graph (this _should_ be a DAG) basd on the given seed.
    """
    def get_seed_stack(seed: Path, mutation: dict) -> List[Tuple[Path, Path]]:
        return [(seed, parent_seed) for parent_seed in
                get_parent_seeds(mutation)]

    mutation = get_mutation_dict(seed)
    seed_stack = get_seed_stack(seed, mutation)

    mutate_graph = nx.DiGraph()
    mutate_graph.add_node(mutation['path'], mutation=mutation)

    # The seed stack is a list of (seed, parent seed) tuples. Once we hit an
    # "orig" seed, parent seed becomes None and we stop
    while seed_stack:
        prev_seed, seed = seed_stack.pop()

        mutation = get_mutation_dict(seed)
        node = mutation['path']
        prev_node = prev_seed

        # If we've already seen this seed before, don't look at it again.
        # Otherwise we'll end up in an infinite loop
        if mutate_graph.has_edge(node, prev_node):
            continue

        mutate_graph.add_node(node, mutation=mutation)
        mutate_graph.add_edge(node, prev_node)

        seed_stack.extend(get_seed_stack(seed, mutation))

    return mutate_graph


def create_node_label(mutation: dict) -> str:
    """Create a meaningful label for a node in the mutation graph."""
    return mutation['path'].name


def create_edge_label(mutation: dict) -> str:
    """Create a meaningful label for an edge in the mutation graph."""
    label_elems = []

    if 'op' in mutation:
        label_elems.append('op: %s' % mutation['op'])
    if 'pos' in mutation:
        label_elems.append('pos: %d' % mutation['pos'])
    if 'val' in mutation:
        label_elems.append('val: %s%d' % (mutation.get('val_type', ''),
                                          mutation['val']))
    if 'rep' in mutation:
        label_elems.append('rep: %d' % mutation['rep'])
    if 'syncing_party' in mutation:
        label_elems.append('sync: %s' % mutation['syncing_party'])

    return ', '.join(label_elems)


def node_shape(mutation: dict) -> str:
    """Decide the Graphviz node shape."""
    if is_crash(mutation):
        return 'hexagon'
    if is_seed(mutation):
        return 'rect'

    return 'oval'


def to_dot_graph(graph: nx.DiGraph) -> nx.DiGraph:
    """Generate a graph that is more ammenable for Graphviz's DOT format."""
    dot_graph = nx.DiGraph()
    node_mapping = {}

    for count, (node, mutation) in enumerate(graph.nodes(data='mutation')):
        dot_graph.add_node(count, shape=node_shape(mutation),
                           label='"%s"' % create_node_label(mutation))
        node_mapping[node] = count

    for u, v in graph.edges():
        mutation = graph.nodes[v]['mutation']
        dot_graph.add_edge(node_mapping[u], node_mapping[v],
                           label='"%s"' % create_edge_label(mutation))

    return dot_graph


def get_path_stats(graph: nx.DiGraph, sources: List[str],
                   sinks: List[str]) -> Tuple[int, int]:
    """
    Get the longest and shortest paths through the graph from a set of source
    nodes to a set of sink nodes.

    Note that this is not very accurate due to splices!!
    """
    paths = [path for sink in sinks
             for source in sources
             for path in nx.all_simple_paths(graph, source, sink)]
    len_calc = lambda f: len(f(paths, key=lambda p: len(p))) + 1

    return len_calc(min), len_calc(max)


def get_mutation_stats(graph: nx.DiGraph) -> Dict[str, int]:
    """Count the number of mutation operators used."""
    ops = defaultdict(int)
    for _, mutation in graph.nodes.data('mutation', default={}):
        if 'op' in mutation:
            ops[mutation['op']] += 1

    return ops


def print_stats(graph: nx.DiGraph) -> None:
    """Print statistics about the mutation graph."""
    sources = [n for n, in_degree in graph.in_degree() if in_degree == 0]
    sinks = [n for n, out_degree in graph.out_degree() if out_degree == 0]
    min_len, max_len = get_path_stats(graph, sources, sinks)
    num_connected_components = nx.number_weakly_connected_components(graph)

    print('num. source nodes: %d' % len(sources))
    print('num. sink nodes: %d' % len(sinks))
    print('num. connected components: %d' % num_connected_components)
    print('shortest mutation chain: %d' % min_len)
    print('longest mutation chain: %d' % max_len)
    print('mutations:')
    for op, count in get_mutation_stats(graph).items():
        print('  %s: %d' % (op, count))


def main():
    """The main function."""
    args = parse_args()

    # Configure logger
    handler = logging.StreamHandler()
    handler.setFormatter(FORMATTER)
    logger.addHandler(handler)
    logger.setLevel(args.log)

    mutation_graph = nx.DiGraph()

    for seed_path in args.seed_path:
        logger.info('Generating mutation graph for %s', seed_path)
        if not seed_path.exists():
            logger.warn('%s does not exist. Skipping...', seed_path)
            continue
        seed_graph = gen_mutation_graph(seed_path)
        mutation_graph.update(seed_graph)

    if len(mutation_graph) == 0:
        logger.error('empty mutation graph')
        sys.exit(1)

    if args.stats:
        print_stats(mutation_graph)

    if args.output:
        write_dot(to_dot_graph(mutation_graph), args.output)

    sys.exit(0)


if __name__ == '__main__':
    main()
