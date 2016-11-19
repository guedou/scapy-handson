# Playing with TLS

The pending [PR #294](playing_with_tls.md) brings a native TLS support to Scapy.

This trophy shows you some cool things that you can do.

## Tasks

**task #1**

- clone a new Scapy git repository from https://github.com/mtury/scapy.git, and
  swith to the tl2 branch
- use `sniff` to capture some HTTPS traffic (i.e. 443/tcp)
- filter packets that have a `TLS` object
- identify a ClientHello or a ServerHello
- display the ciphersuites

**task #2**

- edit the `tls_trophy.py` template
- send a ClientHello
- parse the received data with the `TLS` class
- display the ciphersuite

## Hints

- the TAB key can be use to find Scapy layers
