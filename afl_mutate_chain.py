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


QUEUE_ORIG_SEED_RE = re.compile(r'id:(?P<id>\d+),orig:(?P<orig_seed>\w+)')
QUEUE_MUTATE_SEED_RE = re.compile(r'id:(?P<id>\d+),src:(?P<src>\d+),op:(?P<op>(?!havoc|splice)\w+),pos:(?P<pos>\d+)(?:,val:(?P<val_type>[\w:]+)?(?P<val>[+-]\d+))?')
QUEUE_MUTATE_SEED_HAVOC_RE = re.compile(r'id:(?P<id>\d+),src:(?P<src>\d+),op:(?P<op>havoc,)rep:(?P<rep>\d+)')
QUEUE_MUTATE_SEED_SPLICE_RE = re.compile(r'id:(?P<id>\d+),src:(?P<src1>\d+)\+(?P<src2>\d+),op:(?P<op>splice),rep:(?P<rep>\d+)')


def parse_args():
    parser = ArgumentParser(description='Recover (approximate) mutation chain '
                                        'from an AFL seed')
    parser.add_argument('-d', '--dir', required=True, help='AFL seed directory')
    parser.add_argument('seed', help='Seed to recover mutation chain for')

    return parser.parse_args()


def fix_group_dict(mutate_dict):
    # Remove None values
    mutate_dict = {k:v for k, v in mutate_dict.items() if v is not None}

    # Convert ints
    mutate_dict['id'] = int(mutate_dict['id'])
    if 'src' in mutate_dict:
        mutate_dict['src'] = int(mutate_dict['src'])
    if 'src1' in mutate_dict:
        mutate_dict['src1'] = int(mutate_dict['src1'])
    if 'src2' in mutate_dict:
        mutate_dict['src2'] = int(mutate_dict['src2'])
    if 'pos' in mutate_dict:
        mutate_dict['pos'] = int(mutate_dict['pos'])
    if 'rep' in mutate_dict:
        mutate_dict['rep'] = int(mutate_dict['rep'])
    if 'val' in mutate_dict:
        mutate_dict['val'] = int(mutate_dict['val'])

    return mutate_dict


def find_seed(seed_dir, seed_id):
    seed_path = os.path.join(seed_dir, 'id:%06d,*' % seed_id)
    seed_files = glob.glob(seed_path)

    if not seed_files:
        ret = None
    else:
        ret = seed_files[0]

    return ret


def gen_mutation_chain(seed_path, mutation_chain=None):
    if mutation_chain is None:
        mutation_chain = []
    if seed_path is None:
        return mutation_chain

    seed_dir, seed_name = os.path.split(seed_path)

    match = QUEUE_ORIG_SEED_RE.match(seed_name)
    if match:
        # We've reached the end of the chain. Append the original source to the
        # mutation chain and return
        mutate_dict = fix_group_dict(match.groupdict())
        mutation_chain.append(mutate_dict)

        return mutation_chain

    match = QUEUE_MUTATE_SEED_RE.match(seed_name)
    if match:
        # Recurse on the parent 'src' seed
        mutate_dict = fix_group_dict(match.groupdict())
        mutation_chain.append(mutate_dict)

        parent_seed = find_seed(seed_dir, mutate_dict['src'])
        return gen_mutation_chain(parent_seed, mutation_chain)

    match = QUEUE_MUTATE_SEED_HAVOC_RE.match(seed_name)
    if match:
        # Recurse on the parent 'src' seed
        mutate_dict = fix_group_dict(match.groupdict())
        mutation_chain.append(mutate_dict)

        parent_seed = find_seed(seed_dir, mutate_dict['src'])
        return gen_mutation_chain(parent_seed, mutation_chain)

    match = QUEUE_MUTATE_SEED_SPLICE_RE.match(seed_name)
    if match:
        # Spliced seeds have two parents. Recurse on both
        mutate_dict = fix_group_dict(match.groupdict())
        mutation_chain.append(mutate_dict)

        parent_seed_1 = find_seed(seed_dir, mutate_dict['src1'])
        parent_seed_2 = find_seed(seed_dir, mutate_dict['src2'])

        return gen_mutation_chain(parent_seed_1, mutation_chain) + \
                gen_mutation_chain(parent_seed_2, mutation_chain)

    return mutation_chain


def main():
    args = parse_args()

    seed_dir = args.dir
    if not os.path.isdir(seed_dir):
        raise Exception('%s is not a valid directory' % seed_dir)

    seed_name = args.seed
    seed_path = os.path.join(seed_dir, seed_name)
    if not os.path.isfile(seed_path):
        raise Exception('%s is not a valid seed in %s' % (seed_name, seed_dir))

    mutation_chain = gen_mutation_chain(seed_path)
    print(json.dumps(mutation_chain))


if __name__ == '__main__':
    main()
