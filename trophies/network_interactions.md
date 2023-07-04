# Network Interactions

This trophy is about sending and receiving packets on the network.

## Tasks

### Task #1

- build a simple ICMP packet to `8.8.8.8`
- send it to the network
- display the whole reply using `show()`

### Task #2

- build an implicit ICMP frame (i.e. layer 2) with a TTL value from to 2 to 7
- send it to the network
- use `nsummary()` to show replies
- display the first query, and the second answer
- display the address of the third router on the path
- display the results as hex strings

### Task #3

- send ICMP echo requests using the `sr*()` function that send packets
  forever
- stop the function
- use the `prn` argument to display the source IP address of the replies

### Task #4

- sniff 5 packets on port 443/tcp
- display them in Wireshark (without leaving Scapy)
- write these 5 packets into `test.pcap`
- read them back from the saved PCAP file into the `pkts` variable
- use `+` to concatenate these packets (i.e. build a list of 10 packets)

## Hints

- `sr*()` functions send at layer 3
- `srp*()` functions send at layer 2
- `lsc()` list Scapy functions
