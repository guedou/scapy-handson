# Answering machines

Answering machines can be used to wait for a query and send a reply.

This trophy focus on already created machines, as well as building a new one for
our own protocol.

## Tasks

**task #1**

- choose a builtin AnsweringMachine, and launch it (farpd is easy)
- trigger it by sending a packet with Scapy (arping helps)

**task #2**

- edit the `am_trophy.py` template
- modify the `is_request()` method to match a **Guess**
- modify the `make_reply()` method to return a **Trophy** if the Guess value is
  0x4242, a **Reply** containing 0 is the value is below 0x4242 and 1 otherwise


## Hints

- `git grep AnsweringMachine` will display all Scapy answering machines
