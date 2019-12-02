#!/usr/bin/env python
#
# Reconstructs an approximate AFL mutation chain based on the file names of
# seeds in a queue
#
# Author: Adrian Herrera
#

from __future__ import print_function

from argparse import ArgumentParser
import glob
import json
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
QUEUE_ORIG_SEED_RE = re.compile(r'id:(?P<id>\d+),orig:(?P<orig_seed>\w+)')
QUEUE_MUTATE_SEED_RE = re.compile(r'id:(?P<id>\d+),(?:sig:(?P<sig>\d+),)?src:(?P<src>\d+),op:(?P<op>(?!havoc|splice)\w+),pos:(?P<pos>\d+)(?:,val:(?P<val_type>[\w:]+)?(?P<val>[+-]\d+))?')
QUEUE_MUTATE_SEED_HAVOC_RE = re.compile(r'id:(?P<id>\d+),(?:sig:(?P<sig>\d+),)?src:(?P<src>\d+),op:(?P<op>havoc),rep:(?P<rep>\d+)')
QUEUE_MUTATE_SEED_SPLICE_RE = re.compile(r'id:(?P<id>\d+),(?:sig:(?P<sig>\d+),)?src:(?P<src_1>\d+)\+(?P<src_2>\d+),op:(?P<op>splice),rep:(?P<rep>\d+)')

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
    parser.add_argument('-f', '--output-format', default='json',
                        choices=['json', 'dot'], help='Output format')
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
    seed_path = os.path.join(seed_dir, 'id:%06d,*' % seed_id)
    seed_files = glob.glob(seed_path)

    if not seed_files:
        raise Exception('Could not find seed %s in %s' % (seed_id, seed_dir))

    # Each seed should have a unique ID
    return seed_files[0]


def gen_mutation_chain(seed_path):
    """Recursively generate a mutation chain for the given AFL seed."""
    if seed_path is None:
        return None

    if not os.path.isfile(seed_path):
        raise Exception('%s is not a valid seed file ' % seed_path)

    seed_dir, seed_name = os.path.split(seed_path)

    # If the seed is a crash, move across to the queue
    fuzz_dir, seed_dir_name = os.path.split(seed_dir)
    if seed_dir_name == 'crashes':
        seed_dir = os.path.join(fuzz_dir, 'queue')

    match = QUEUE_ORIG_SEED_RE.match(seed_name)
    if match:
        # We've reached the end of the chain
        mutate_dict = fix_regex_dict(match.groupdict())

        mutate_dict['path'] = os.path.realpath(seed_path)

        return mutate_dict

    match = QUEUE_MUTATE_SEED_RE.match(seed_name)
    if match:
        # Recurse on the parent 'src' seed
        mutate_dict = fix_regex_dict(match.groupdict())
        parent_seed = find_seed(seed_dir, mutate_dict['src'])

        mutate_dict['path'] = os.path.realpath(seed_path)
        mutate_dict['src'] = [gen_mutation_chain(parent_seed)]

        return mutate_dict

    match = QUEUE_MUTATE_SEED_HAVOC_RE.match(seed_name)
    if match:
        # Recurse on the parent 'src' seed
        mutate_dict = fix_regex_dict(match.groupdict())
        parent_seed = find_seed(seed_dir, mutate_dict['src'])

        mutate_dict['path'] = os.path.realpath(seed_path)
        mutate_dict['src'] = [gen_mutation_chain(parent_seed)]

        return mutate_dict

    match = QUEUE_MUTATE_SEED_SPLICE_RE.match(seed_name)
    if match:
        # Spliced seeds have two parents. Recurse on both
        mutate_dict = fix_regex_dict(match.groupdict())
        parent_seed_1 = find_seed(seed_dir, mutate_dict.pop('src_1'))
        parent_seed_2 = find_seed(seed_dir, mutate_dict.pop('src_2'))

        mutate_dict['path'] = os.path.realpath(seed_path)
        mutate_dict['src'] = [gen_mutation_chain(parent_seed_1),
                              gen_mutation_chain(parent_seed_2)]

        return mutate_dict

    raise Exception('Failed to find parent seed for `%s`' % seed_name)


def create_edge_label(mutate_dict):
    """Create a meaningful label for the mutation graph."""
    label = 'op: %s' % mutate_dict['op']
    if 'pos' in mutate_dict:
        label = '%s, pos: %d' % (label, mutate_dict['pos'])
    if 'val' in mutate_dict:
        label = '%s, val: %s%d' % (label, mutate_dict.get('val_type', ''),
                                   mutate_dict['val'])
    if 'rep' in mutate_dict:
        label = '%s, rep: %d' % (label, mutate_dict['rep'])

    return label


def create_graph(mutation_chains, graph=None):
    """Recursively produce a graphviz graph of the mutation chain(s)."""
    if not graph:
        graph = nx.DiGraph()

    for mutation_chain in mutation_chains:
        for src in mutation_chain.get('src', []):
            if 'orig_seed' in src:
                graph.add_edge(src['orig_seed'], mutation_chain['id'],
                               label='"%s"' % create_edge_label(mutation_chain))
            else:
                graph.add_edge(src['id'], mutation_chain['id'],
                               label='"%s"' % create_edge_label(mutation_chain))
                create_graph([src], graph)

    return graph


def main():
    """The main function."""
    args = parse_args()
    mutation_chains = []

    for seed_path in args.seed_path:
        mutation_chains.append(gen_mutation_chain(seed_path))

    if args.output_format == 'json':
        print(json.dumps(mutation_chains))
    elif args.output_format == 'dot':
        write_dot(create_graph(mutation_chains), sys.stdout)


if __name__ == '__main__':
    main()
