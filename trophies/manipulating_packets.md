# Manipulating packets

This trophy gives yoy the opportunity to perfom simple Scapy packets manipulation.

## Tasks

**task #1**

- create a valid DNS query to `8.8.8.8`
- display its summary
- access the source address computed by Scapy
- use the `sprintf()` method to display the source UDP port
- access the layer before the DNS one
- access the UDP layer

**task #2**

- create an implicit packet that builds 5 explicit packets with 5 differents TTL values
- iterate over this packets

## Hints

- `ls()` list Scapy protocols names
- `ls(PROTO)` list the fields of the _PROTO_ protocol
- the `/` operator stacks protocols
- four Scapy protocol headers are required
