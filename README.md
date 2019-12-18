# AFL Mutation Graph

Recovers an approximation of the mutation graph (specifically, a DAG) that led
to a particular seed (or set of seeds) in an
[AFL](http://lcamtuf.coredump.cx/afl/) queue. The graph can be saved in Graphviz
DOT format.

To graph the relationships between all queue inputs:

```bash
python afl_mutation_graph.py $(find queue/ -wholename 'queue/id:*') -o queue.dot
dot -Tpdf -O queue.dot
```

Example mutation graph, starting from a corpus of seeds (in rectangles).
Hexagon nodes are crashing seeds:

![mutation graph example](img/mutate_graph_example.png "mutation graph example")
