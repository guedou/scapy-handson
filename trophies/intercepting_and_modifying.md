# Intercepting and modifying packets

This trophy shows howto use Scapy with NFQUEUE in order to tag and modify
packets on the fly.

## Tasks

**task #1**

- edit the `nfq_trophy.py` template
- trigger a packet with `dig` to get the IP address of grehack.fr
- check if it works as expected


**task #2**

- parse the packet with Scapy
- check if it contains as DNS header
- remove checksums and lengths
- use `set_verdict_modified()` to send the packet processed by Scapy
  - argument #1 is NF_ACCEPT, argument #2 is the packet string, argument #3 is the length
 
**task #3**

- iterate over the received DNS Resource Records
- identify the grehack.fr address
- change it to 127.0.0.1

## Hints

- on Debian, install the `python-nfqueue` module
- DNS is an *old* Scapy protocol, parsing then building might not give the same
  packet: you need to remove lengths
