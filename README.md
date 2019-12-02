# AFL Mutation Chain

Recovers an approximation of the mutation chain that led to a particular seed in
an [AFL](http://lcamtuf.coredump.cx/afl/) queue.  Outputs the chain in either
JSON or Graphviz DOT format.

To graph the relationships between all queue inputs:

```bash
python afl_mutation_chain.py -f dot $(find queue/ -wholename 'queue/id:*') > queue.dot
dot -Tpdf queue.dot > queue.pdf
```

Example mutation chain, starting from the initial seed `seed`:

![mutation chain example](etc/mutate_chain_example.png "mutation chain example")
