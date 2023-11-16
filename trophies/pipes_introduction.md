# Pipes Introduction

Pipes are not a well known Scapy feature. They can be used to chain actions such
as sniffing, modifying and printing packets.

This trophy provides simple examples that builds on a silly one that does
nothing.

## Tasks

### Task #1

- edit the `pipe_trophy.py` template
- add a `ConsoleSink()` named `cs`
- redirect `clfs` to `cs` (with the `>` operator)
- launch the script

### Task #2

- remove the `clfs` to cs redirection
- add a `TransformDrain()` named `td` that uses `transform_f()`
- add a `InjectSink()` named `ijs`
- redirect `clfs` to `td`, and `td` to `ijs`
- test it:
  - sniff the network
  - launch the script

### Task #3### T

- add a `WrpcapSink()` named `ws`
- redirect `td` to `ws`
- sniff the network and check for a newly created PCAP file
- launch the script

## Hints

- in Scapy sources, the files `pipetool.py` and `scapypipes.py` give you all you
  need to know about pipes related objects
- a Sink is the last element of a pipe, a Drain 'manipulates' data and forwards
  it
