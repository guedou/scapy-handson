# Playing with TLS

This trophy shows you some cool things that you can do.

## Tasks

### Task #1

- load the `tls` layer with `load_layer()`
- use `sniff` to capture some HTTPS traffic (i.e. 443/tcp)
- filter packets that have a `TLS` object
- identify a ClientHello or a ServerHello message
- display the ciphersuites

### Task #2

- use `tcpdump` to sniff all packets on 443/TCP sent to `grehack.fr` and write them to `grehack.fr.pcap`
- use `curl` to connect to `https://grehack.fr` and use the `SSLKEYLOGFILE` environment variable to dump session keys to `grehack.fr.keys.log`
- use `editcap` to merge the two files `grehack.fr.keys.log` and `grehack.fr.pcap` into `grehack.fr.pcapng`
- import the PCAPng file in Scapy using `rdpcap()` and look for unencrypted strings!

## Hints

- the TAB key can be used to find Scapy layers names!
- check the help message of the `editcap` `--inject-keys` parameter
