#!/usr/bin/env python

"""
Reconstructs an approximate AFL mutation chain based on the file names of seeds
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
QUEUE_MUTATE_SEED_SYNC_RE = re.compile(r'id[:_](?P<id>\d+),sync[:_](?P<syncing_party>[\w]+),src[:_](?P<src>\d+)')

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
    parser = ArgumentParser(description='Recover (approximate) mutation chain '
                                        'from an AFL seed')
    parser.add_argument('seed_path', nargs='+',
                        help='Path to the seed(s) to recover mutation chain')

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

        return mutate_dict, [(seed_path, None)]

    match = QUEUE_MUTATE_SEED_RE.match(seed_name)
    if match:
        # Recurse on the parent 'src' seed
        mutate_dict = fix_regex_dict(match.groupdict())
        mutate_dict['path'] = seed_path

        src = mutate_dict['src']

        return mutate_dict, [(seed_path, find_seed(seed_dir, src))]

    match = QUEUE_MUTATE_SEED_HAVOC_RE.match(seed_name)
    if match:
        # Recurse on the parent 'src' seed
        mutate_dict = fix_regex_dict(match.groupdict())
        mutate_dict['path'] = seed_path

        src = mutate_dict['src']

        return mutate_dict, [(seed_path, find_seed(seed_dir, src))]

    match = QUEUE_MUTATE_SEED_SPLICE_RE.match(seed_name)
    if match:
        # Spliced seeds have two parents. Recurse on both
        mutate_dict = fix_regex_dict(match.groupdict())
        mutate_dict['path'] = seed_path

        src_1 = mutate_dict['src_1']
        src_2 = mutate_dict['src_2']

        return mutate_dict, [(seed_path, find_seed(seed_dir, src_1)),
                             (seed_path, find_seed(seed_dir, src_2))]

    match = QUEUE_MUTATE_SEED_SYNC_RE.match(seed_name)
    if match:
        # Seed synced from another fuzzer node
        mutate_dict = fix_regex_dict(match.groupdict())
        mutate_dict['path'] = seed_path

        seed_dir = os.path.join(os.path.dirname(os.path.dirname(seed_dir)),
                                mutate_dict['syncing_party'], 'queue')
        src = mutate_dict['src']

        return mutate_dict, [(seed_path, find_seed(seed_dir, src))]

    raise Exception('Failed to find parent seed for `%s`' % seed_name)


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


def create_node_label(mutate_dict):
    """Create a meaningful label for a node in the mutation graph."""
    return os.path.basename(mutate_dict['path'])


def node_shape(mutate_dict):
    """Decide the Graphviz node shape."""
    if is_crash_seed(mutate_dict):
        return 'hexagon'
    elif 'orig_seed' in mutate_dict:
        return 'rect'

    return 'oval'


def is_crash_seed(mutate_dict):
    """Returns `True` if the given mutation dict is for a crashing seed."""
    return 'crashes' in os.path.basename(os.path.dirname(mutate_dict['path']))


def gen_mutation_graph(seed_path):
    """
    Generate a mutation graph (this _should_ be a DAG) basd on the given seed.
    """

    if not os.path.isfile(seed_path):
        raise Exception('%s is not a valid seed file' % seed_path)

    seed_path = os.path.realpath(seed_path)
    mutate_dict, seed_stack = get_mutation_dict(seed_path)

    mutate_graph = nx.DiGraph()
    mutate_graph.add_node(mutate_dict['path'], mutation=mutate_dict)

    # The seed stack is a list of (seed, parent seed) tuples. Once we hit an
    # "orig" seed, parent seed becomes None and we stop
    while seed_stack:
        prev_seed_path, seed_path = seed_stack.pop()
        if not seed_path:
            continue

        mutate_dict, parent_seeds = get_mutation_dict(seed_path)
        node = mutate_dict['path']
        prev_node = prev_seed_path

        # If we've already seen this seed before, don't look at it again.
        # Otherwise we'll end up in an infinite loop
        if node in mutate_graph:
            continue

        mutate_graph.add_node(node, mutation=mutate_dict)
        mutate_graph.add_edge(node, prev_node)

        seed_stack.extend(parent_seeds)

    return mutate_graph


def to_dot_graph(graph):
    """Generate a graph that is more ammenable for Graphviz's DOT format."""
    dot_graph = nx.DiGraph()
    node_mapping = {}

    for count, (node, mutate_dict) in enumerate(graph.nodes(data='mutation')):
        dot_graph.add_node(count, shape=node_shape(mutate_dict),
                           label='"%s"' % create_node_label(mutate_dict))
        node_mapping[node] = count

    for u, v in graph.edges():
        mutate_dict = graph.nodes[u]['mutation']
        dot_graph.add_edge(node_mapping[u], node_mapping[v],
                           label='"%s"' % create_edge_label(mutate_dict))

    return dot_graph


def main():
    """The main function."""
    args = parse_args()

    mutation_graph = nx.DiGraph()
    for seed_path in args.seed_path:
        mutation_graph.update(gen_mutation_graph(seed_path))

    write_dot(to_dot_graph(mutation_graph), sys.stdout)


if __name__ == '__main__':
    main()
