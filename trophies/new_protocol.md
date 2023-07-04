# Adding a new protocol

This trophy shows you how to implement a new protocol into Scapy.

## Tasks

### Task #1

- edit the `templates/proto_trophy.py` file
- modify the `GreHack` packet
- add a `ByteField` named **id**
- add a `ByteEnumField` named **type** (type 0 is called **Guess**, type 1 is
  **Reply**, and type 2 **Trophy**)
- add a `IntField` named **value**

### Task #2

- modify `hashret()` to return the packed **id** (i.e. a single byte, not an
  integer)
- modify `answers()` to return `True` if the packet is an answer to `other`
- check the results of the unit tests

### Task #3

- use the `bind_layers()` function to tell Scapy that the GreHack protocol is on
  top of UDP with source and destination ports equal to 1811
- check the results of the unit tests

## Hints

- protocols inherit from `Packet`, have a name, and field description
- `hashret()` is used by Scapy to ease matching Queries and Replies
- `answers()` is used by Scapy to find if a packet is a reply to another one
