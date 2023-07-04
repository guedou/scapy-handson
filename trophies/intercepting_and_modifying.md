# Intercepting and Modifying Packets

This trophy shows how to use Scapy with NFQUEUE in order to tag and modify
packets on the fly. It only works on Linux with Python2.

You need to follow the instructions on https://github.com/oremanj/python-netfilterqueue to install finally be able to intall the module with:
```
pip install NetfilterQueue
```

## Tasks

### Task #1

- edit the `templates/nfq_trophy.py` file
- trigger a packet with `dig` to get the IP address of `grehack.fr`
- check if it works as expected

### Task #2

- parse the packet with Scapy
- check if it contains a DNS header
- remove checksums and lengths
- use `set_payload()` to send the packet processed by Scapy

### Task #3

- iterate over the received DNS Resource Records
- identify the grehack.fr address
- change it to 127.0.0.1

## Hints

- DNS is an *old* Scapy protocol, parsing then building might not give the same packet: you need to remove length fields
