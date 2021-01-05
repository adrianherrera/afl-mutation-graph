# AFL Mutation Graph

Recovers an approximation of the mutation graph (specifically, a DAG) that led
to a particular seed (or set of seeds) in an
[AFL](http://lcamtuf.coredump.cx/afl/)/]AFL++](https://aflplus.plus/) queue.
The graph can be saved in Graphviz DOT format.

To graph the relationships between all queue inputs:

```bash
python afl_mutation_graph.py -o queue.dot $(find queue/ -wholename 'queue/id:*')
dot -Tpdf -O queue.dot
```

Example mutation graph, starting from a corpus of seeds (in rectangles).
Hexagon nodes are crashing seeds:

![mutation graph example](img/mutate_graph_example.png "mutation graph example")
