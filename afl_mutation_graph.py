#!/usr/bin/env python

"""
Reconstructs an approximate AFL mutation graph based on the file names of seeds
in a queue.

Author: Adrian Herrera
"""


from __future__ import print_function

from argparse import ArgumentParser
import glob
import os
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
QUEUE_ORIG_SEED_RE = re.compile(r'id[:_](?P<id>\d+),orig[:_](?P<orig_seed>\w+)')
QUEUE_MUTATE_SEED_RE = re.compile(r'id[:_](?P<id>\d+),(?:sig[:_](?P<sig>\d+),)?src[:_](?P<src>\d+),op[:_](?P<op>(?!havoc|splice)\w+),pos[:_](?P<pos>\d+)(?:,val[:_](?P<val_type>[\w:_]+)?(?P<val>[+-]\d+))?')
QUEUE_MUTATE_SEED_HAVOC_RE = re.compile(r'id[:_](?P<id>\d+),(?:sig[:_](?P<sig>\d+),)?src[:_](?P<src>\d+),op[:_](?P<op>havoc),rep[:_](?P<rep>\d+)')
QUEUE_MUTATE_SEED_SPLICE_RE = re.compile(r'id[:_](?P<id>\d+),(?:sig[:_](?P<sig>\d+),)?src[:_](?P<src_1>\d+)\+(?P<src_2>\d+),op[:_](?P<op>splice),rep[:_](?P<rep>\d+)')
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
}

# Regex elements to convert to ints
CONVERT_TO_INTS = ('id', 'sig', 'src', 'src_1', 'src_2', 'pos', 'rep', 'val')


def parse_args():
    """Parse command-line arguments."""
    parser = ArgumentParser(description='Recover (approximate) mutation graph'
                                        'from a set of AFL seeds')
    parser.add_argument('-s', '--stats', required=False, action='store_true',
                        help='Print statistics about the mutation graph')
    parser.add_argument('-o', '--output', required=False,
                        help='Output path for DOT file')
    parser.add_argument('seed_path', nargs='+',
                        help='Path to the seed(s) to recover mutation graph')

    return parser.parse_args()


def fix_regex_dict(mutate_dict):
    """
    Fix the groupdict returned by the regex match.

    Convert strings to int, etc.
    """
    # Remove None values
    mutate_dict = {k:v for k, v in mutate_dict.items() if v is not None}

    # Convert ints
    for key in CONVERT_TO_INTS:
        if key in mutate_dict:
            mutate_dict[key] = int(mutate_dict[key])

    # Expand op names to full stage names
    if 'op' in mutate_dict:
        mutate_dict['op'] = OP_MAPPING[mutate_dict['op']]

    return mutate_dict


def find_seed(seed_dir, seed_id):
    """Find a seed file with the given ID."""
    seed_path = os.path.join(seed_dir, 'id[:_]%06d,*' % seed_id)
    seed_files = glob.glob(seed_path)

    if not seed_files:
        raise Exception('Could not find seed %s in %s' % (seed_id, seed_dir))

    # Each seed should have a unique ID
    return seed_files[0]


def is_crash(mutate_dict):
    """Returns `True` if the given mutation dict is for a crashing input."""
    return 'crashes' in os.path.basename(os.path.dirname(mutate_dict['path']))


def is_seed(mutate_dict):
    """
    Returns `True` if the given mutation dict is for a seed from the fuzzing
    corpus.
    """
    return 'orig_seed' in mutate_dict


def get_parent_seeds(mutate_dict):
    """Get a list of parent seeds from the given mutation dictionary."""
    seed_dir = os.path.dirname(mutate_dict['path'])

    # If the seed is a crash, move across to the queue
    if is_crash(mutate_dict):
        seed_dir = os.path.join(os.path.dirname(seed_dir), 'queue')

    if 'orig_seed' in mutate_dict:
        return []
    elif 'syncing_party' in mutate_dict:
        seed_dir = os.path.join(os.path.dirname(os.path.dirname(seed_dir)),
                                mutate_dict['syncing_party'], 'queue')
        return [find_seed(seed_dir, mutate_dict['src'])]
    elif 'src_1' in mutate_dict:
        return [find_seed(seed_dir, mutate_dict['src_1']),
                find_seed(seed_dir, mutate_dict['src_2'])]
    elif 'src' in mutate_dict:
        return [find_seed(seed_dir, mutate_dict['src'])]

    raise Exception('Invalid mutation dictionary %s' % mutate_dict)


def get_mutation_dict(seed_path):
    """
    Parse out a mutation dict from the given seed.

    Returns a tuple of:

        1. Mutation dict
        2. List of (current seed, parent) tuples
    """
    seed_dir, seed_name = os.path.split(seed_path)
    seed_path = os.path.realpath(seed_path)

    # If the seed is a crash, move across to the queue
    fuzz_dir, seed_dir_name = os.path.split(seed_dir)
    if seed_dir_name == 'crashes':
        seed_dir = os.path.join(fuzz_dir, 'queue')

    match = QUEUE_ORIG_SEED_RE.match(seed_name)
    if match:
        # We've reached the end of the chain
        mutate_dict = fix_regex_dict(match.groupdict())
        mutate_dict['path'] = seed_path

        return mutate_dict

    match = QUEUE_MUTATE_SEED_RE.match(seed_name)
    if match:
        # Recurse on the parent 'src' seed
        mutate_dict = fix_regex_dict(match.groupdict())
        mutate_dict['path'] = seed_path

        return mutate_dict

    match = QUEUE_MUTATE_SEED_HAVOC_RE.match(seed_name)
    if match:
        # Recurse on the parent 'src' seed
        mutate_dict = fix_regex_dict(match.groupdict())
        mutate_dict['path'] = seed_path

        return mutate_dict

    match = QUEUE_MUTATE_SEED_SPLICE_RE.match(seed_name)
    if match:
        # Spliced seeds have two parents. Recurse on both
        mutate_dict = fix_regex_dict(match.groupdict())
        mutate_dict['path'] = seed_path

        return mutate_dict

    match = QUEUE_MUTATE_SEED_SYNC_RE.match(seed_name)
    if match:
        # Seed synced from another fuzzer node
        mutate_dict = fix_regex_dict(match.groupdict())
        mutate_dict['path'] = seed_path

        return mutate_dict

    raise Exception('Failed to find parent seed for `%s`' % seed_name)


def gen_mutation_graph(seed_path):
    """
    Generate a mutation graph (this _should_ be a DAG) basd on the given seed.
    """

    if not os.path.isfile(seed_path):
        raise Exception('%s is not a valid seed file' % seed_path)

    get_seed_stack = lambda sp, md: [(sp, ps) for ps in get_parent_seeds(md)]

    seed_path = os.path.realpath(seed_path)
    mutate_dict = get_mutation_dict(seed_path)
    seed_stack = get_seed_stack(seed_path, mutate_dict)

    mutate_graph = nx.DiGraph()
    mutate_graph.add_node(mutate_dict['path'], mutation=mutate_dict)

    # The seed stack is a list of (seed, parent seed) tuples. Once we hit an
    # "orig" seed, parent seed becomes None and we stop
    while seed_stack:
        prev_seed_path, seed_path = seed_stack.pop()

        mutate_dict = get_mutation_dict(seed_path)
        node = mutate_dict['path']
        prev_node = prev_seed_path

        # If we've already seen this seed before, don't look at it again.
        # Otherwise we'll end up in an infinite loop
        if mutate_graph.has_edge(node, prev_node):
            continue

        mutate_graph.add_node(node, mutation=mutate_dict)
        mutate_graph.add_edge(node, prev_node)

        seed_stack.extend(get_seed_stack(seed_path, mutate_dict))

    return mutate_graph


def create_node_label(mutate_dict):
    """Create a meaningful label for a node in the mutation graph."""
    return os.path.basename(mutate_dict['path'])


def create_edge_label(mutate_dict):
    """Create a meaningful label for an edge in the mutation graph."""
    label_elems = []

    if 'op' in mutate_dict:
        label_elems.append('op: %s' % mutate_dict['op'])
    if 'pos' in mutate_dict:
        label_elems.append('pos: %d' % mutate_dict['pos'])
    if 'val' in mutate_dict:
        label_elems.append('val: %s%d' % (mutate_dict.get('val_type', ''),
                                          mutate_dict['val']))
    if 'rep' in mutate_dict:
        label_elems.append('rep: %d' % mutate_dict['rep'])
    if 'syncing_party' in mutate_dict:
        label_elems.append('sync: %s' % mutate_dict['syncing_party'])

    return ', '.join(label_elems)


def node_shape(mutate_dict):
    """Decide the Graphviz node shape."""
    if is_crash(mutate_dict):
        return 'hexagon'
    elif is_seed(mutate_dict):
        return 'rect'
    else:
        return 'oval'


def to_dot_graph(graph):
    """Generate a graph that is more ammenable for Graphviz's DOT format."""
    dot_graph = nx.DiGraph()
    node_mapping = {}

    for count, (node, mutate_dict) in enumerate(graph.nodes(data='mutation')):
        dot_graph.add_node(count, shape=node_shape(mutate_dict),
                           label='"%s"' % create_node_label(mutate_dict))
        node_mapping[node] = count

    for u, v in graph.edges():
        mutate_dict = graph.nodes[v]['mutation']
        dot_graph.add_edge(node_mapping[u], node_mapping[v],
                           label='"%s"' % create_edge_label(mutate_dict))

    return dot_graph


def get_path_stats(graph, sources, sinks):
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


def print_stats(graph):
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


def main():
    """The main function."""
    args = parse_args()

    mutation_graph = nx.DiGraph()

    for seed_path in args.seed_path:
        mutation_graph.update(gen_mutation_graph(seed_path))

    if args.stats:
        print_stats(mutation_graph)

    if args.output:
        write_dot(to_dot_graph(mutation_graph), args.output)


if __name__ == '__main__':
    main()
