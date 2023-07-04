# Scapy Hands-on

This file contains possible solutions for the trophies!

## Trophy 1 - Manipulating Packets

### Task #1

```python
>>> p = IP(dst="8.8.8.8") / UDP() / DNS()

>>> p.summary()
'IP / UDP / DNS Qry "www.example.com" '

>>> p.src
'172.20.10.2'

>>> p.sprintf("%UDP.sport%")
'domain'

>>> p[UDP]
<UDP  sport=domain |<DNS  qd=<DNSQR  |> |>>

>>> p[DNS].underlayer
<UDP  sport=domain |<DNS  qd=<DNSQR  |> |>>
```

### Task #2

```python
>>> p = IP(ttl=(1, 5)) / ICMP()

>>> [packet for packet in p]
[<IP  frag=0 ttl=1 proto=icmp |<ICMP  |>>, <IP  frag=0 ttl=2 proto=icmp |<ICMP |>>, <IP  frag=0 ttl=3 proto=icmp |<ICMP  |>>, <IP  frag=0 ttl=4 proto=icmp |<ICMP  |>>, <IP  frag=0 ttl=5 proto=icmp |<ICMP  |>>]
```

## Trophy 2 - Network Interactions

### Task #1

```python
>>> p = IP(dst="8.8.8.8") / ICMP()

>>> r = sr1(p)
Begin emission:
Finished to send 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets

>>> r.show()
###[ IP ]### 
  version= 4
  ihl= 5
  tos= 0x0
  len= 28
  id= 46863
  flags= 
  frag= 0
  ttl= 52
  proto= icmp
  chksum= 0x9ac
  src= 8.8.8.8
  dst= 172.20.10.2
  \options\
###[ ICMP ]### 
     type= echo-reply
     code= 0
     chksum= 0xffff
     id= 0x0
     seq= 0x0
```

### Task #2

```python
>>> p = Ether() / IP(dst="8.8.8.8", ttl=(2, 7)) / ICMP()

>>> r, u = srp(p)
Begin emission:
Finished to send 6 packets.
******
Received 6 packets, got 6 answers, remaining 0 packets

>>> r.nsummary()
0000 Ether / IP / ICMP 172.20.10.2 > 8.8.8.8 echo-request 0 ==> Ether / IP / ICMP 10.164.24.1 > 172.20.10.2 time-exceeded ttl-zero-during-transit / IPerror / ICMPerror
0001 Ether / IP / ICMP 172.20.10.2 > 8.8.8.8 echo-request 0 ==> Ether / IP / ICMP 10.164.26.49 > 172.20.10.2 time-exceeded ttl-zero-during-transit / IPerror / ICMPerror
0002 Ether / IP / ICMP 172.20.10.2 > 8.8.8.8 echo-request 0 ==> Ether / IP / ICMP 10.164.26.62 > 172.20.10.2 time-exceeded ttl-zero-during-transit / IPerror / ICMPerror
0003 Ether / IP / ICMP 172.20.10.2 > 8.8.8.8 echo-request 0 ==> Ether / IP / ICMP 10.164.26.54 > 172.20.10.2 time-exceeded ttl-zero-during-transit / IPerror / ICMPerror
0004 Ether / IP / ICMP 172.20.10.2 > 8.8.8.8 echo-request 0 ==> Ether / IP / ICMP 10.164.26.65 > 172.20.10.2 time-exceeded ttl-zero-during-transit / IPerror / ICMPerror
0005 Ether / IP / ICMP 172.20.10.2 > 8.8.8.8 echo-request 0 ==> Ether / IP / ICMP 193.252.137.89 > 172.20.10.2 time-exceeded ttl-zero-during-transit / IPerror / ICMPerror

>>> r[0].query
<Ether  type=IPv4 |<IP  frag=0 ttl=2 proto=icmp dst=8.8.8.8 |<ICMP  |>>>

>>> r[1].answer
<Ether  dst=b8:e8:56:45:8c:e6 src=b8:26:6c:5f:4e:ee type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=56 id=0 flags= frag=0 ttl=253 proto=icmp chksum=0xbeaf src=193.253.82.102 dst=192.168.42.9 |<ICMP  type=time-exceeded code=ttl-zero-during-transit chksum=0xf4ff reserved=0 length=0 unused=0 |<IPerror  version=4 ihl=5 tos=0x0 len=28 id=1 flags= frag=0 ttl=1 proto=icmp chksum=0xbf1f src=192.168.42.9 dst=8.8.8.8 |<ICMPerror  type=echo-request code=0 chksum=0xf7ff id=0x0 seq=0x0 |>>>>>

>>> r[2].answer[IP].src
'10.164.26.49'

>>> r.hexdump()
0000 15:11:57.044691 Ether / IP / ICMP 172.20.10.2 > 8.8.8.8 echo-request 0 ==> Ether / IP / ICMP 10.164.24.1 > 172.20.10.2 time-exceeded ttl-zero-during-transit / IPerror / ICMPerror
0000  B8E856458CE63A71DE900B6408004500 ..VE..:q...d..E.
0010  003800010000FE01E4080AA41801AC14 .8..............
0020  0A020B002155000000004500001C0001 ....!U....E.....
0030  00000101F3BAAC140A02080808080800 ................
0040  CBAA00000000                     ......
0001 15:11:57.047029 Ether / IP / ICMP 172.20.10.2 > 8.8.8.8 echo-request 0 ==> Ether / IP / ICMP 10.164.26.49 > 172.20.10.2 time-exceeded ttl-zero-during-transit / IPerror / ICMPerror
0000  B8E856458CE63A71DE900B6408004500 ..VE..:q...d..E.
0010  0038DAAC0000FC01092D0AA41A31AC14 .8.......-...1..
0020  0A020B002155000000004500001C0001 ....!U....E.....
0030  00000101F3BAAC140A02080808080800 ................
0040  CBAA00000000
[.. truncated ..]
```

### Task #3

```python
>>> srloop(IP(dst="8.8.8.8") / ICMP())
[.. truncated ..]

>>> srloop(IP(dst="8.8.8.8") / ICMP(), prn=lambda p: p[1].src)
[.. truncated ..]
```

### Task #4

```python
>>> sniff(filter="port 443", count=5)
<Sniffed: TCP:5 UDP:0 ICMP:0 Other:0>
>>> s = _

>>> wireshark(s)

>>> wrpcap("test.pcap", s)

>>> pkts = rdpcap("test.pcap")

>>> s + pkts
<Sniffed+test.pcap: TCP:10 UDP:0 ICMP:0 Other:0>
```

## Trophy 3 - Interactions and Modifying Packets

The following command can be used to trigger the DNS answer:

```shell
dig @8.8.8.8 grehack.fr A
```

At the end, the callback is the following:

```python
def scapy_callback(packet):
    # Get the data
    data = packet.get_payload()

    # Parse the DNS packet with Scapy
    p = IP(data)
    # Check if it contains a DNS header
    if p.getlayer(DNS):
        # Remove checksums and lengths
        del(p[IP].chksum, p[IP].len, p[UDP].chksum, p[UDP].len)

        # Iterate over the received DNS Resource Records
        for dns_an in p[DNS].an:
            # Identify the grehack.fr address and change it to 127.0.0.1
            print(dns_an.rrname, dns_an.type)
            if dns_an.rrname == b"grehack.fr." and dns_an.type == 1:  # 'A' DNS query
                dns_an.rdata = b"127.0.0.1"
                print("bla")
                break

        # Rebuild the packet
        s = raw(p)
        # Set the verdict and return the new packet
        packet.set_payload(s)
             
    # Accept the packet
    packet.accept()
```

## Trophy 4 - IPv6 Reconnaissance

### Task #1

```python
>>> p = IPv6() / ICMPv6ND_RS()

>>> r = sr1(p)
```

### Task #2

```python
>>> p = IPv6(dst="ff02::1") / ICMPv6EchoRequest()

>>> conf.checkIPsrc = False

>>> r = sr1(p)
```

### Task #3

```python
>>> conf.checkIPsrc = False

>>> p = IPv6(dst="ff02::1") / ICMPv6EchoRequest()

>>> srloop(p, multi=1, prn=lambda sr: sr[1][IPv6].src)
```

## Trophy 5 - Visualizations

## Task #1

```python
>>> p = IPv6() / ICMPv6EchoRequest()

>>> raw(p)

>>> hexdump(p)

>>> p.show()
>>> p.show2()

>>> p.pdfdump()  # set conf.prog.pdfreader to a valid program on your installation
```

### Task #2

```python
>>> ans, unans = srloop(IP(dst=["8.8.8.8", "8.8.4.4"]) / ICMP(), inter=.1, timeout=.1, count=100, verbose=False)

>>> ans.multiplot(lambda sr: (sr[1][IP].src, (sr[1].time, sr[1][IP].id)), plot_xy=True)
```

## Trophy 6 - Fun With X.509 Certificates

You might need to install the python `ecdsa` plugin to enable Certificate manipulation tools.

### Task #1

```python
>>> load_layer("tls")

>>> der_bytes = open("grehack.fr.der", "rb").read()
>>> pem_bytes = der2pem(der_bytes, obj="CERTIFICATE")
>>> open("grehack.fr.pem", "wb").write(pem_bytes)

# If you could only retrieve the certificate as PEM
>>> pem_bytes = open("grehack.fr.pem", "rb").read()
>>> der_bytes = pem2der(pem_bytes)

>>> c = X509_Cert(der_bytes)

>>> c.signatureValue
<_Raw_ASN1_BIT_STRING[1000000000...0001010011]=b'\x80+8LsRD\x1c\xf9\x04...\x06\xaf\xf7\x1cz\xf8e@|S' (0 unused bit)>

>>> c.tbsCertificate.subject
[<X509_RDN  rdn=[<X509_AttributeTypeAndValue  type=<ASN1_OID['commonName']> value=<ASN1_PRINTABLE_STRING[b'grehack.fr']> |>] |>]

>>> [e.extnValue for e in c.tbsCertificate.extensions if type(e.extnValue) == X509_ExtAuthInfoAccess]
[<X509_ExtAuthInfoAccess  authorityInfoAccess=[<X509_AccessDescription  accessMethod=<ASN1_OID['ocsp']> accessLocation=<X509_GeneralName  generalName=<X509_URI  uniformResourceIdentifier=<ASN1_IA5_STRING[b'http://r3.o.lencr.org']> |> |> |>, <X509_AccessDescription  accessMethod=<ASN1_OID['caIssuers']> accessLocation=<X509_GeneralName  generalName=<X509_URI  uniformResourceIdentifier=<ASN1_IA5_STRING[b'http://r3.i.lencr.org/']> |> |> |>] |>]
```

Check the content of the PEM file with:

```shell
openssl x509 -noout -text -in grehack.fr.pem
```

### Task #2

```python
>>> c = Cert("grehack.fr.der")

>>> c.remainingDays()
64.64104166666667

>>> c.isSelfSigned()
False
```

### Task #3

Generate an RSA private key with:

```shell
openssl genrsa -out priv.key
```

```python
>>> pk = PrivKey("priv.key")
>>> c = Cert("grehack.fr.der")
>>> c.tbsCertificate.serialNumber = 0x2807

>>> new_cert = pk.resignCert(c.x509Cert)
>>> open("new_cert.pem", "bw").write(der2pem(raw(new_cert), obj="CERTIFICATE"))

>>> pk.verifyCert(new_cert)
True
```

Check the new certificate serial value with:

```shell
openssl x509 -noout -text -in new_cert.pem |grep -i serial
        Serial Number: 10247 (0x2807)
```

## Trophy 7 - Playing With TLS

### Task #1

```python
>>> load_layer("tls")

>>> s = sniff(filter="tcp port 443")

>>> filtered = [x for x in s if TLS in x]

>>> ch = [p for p in filtered if TLSClientHello in p]

>>> ch[0][TLS].msg[0].ciphers
[4866, 4867, 4865, 49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255]
```

### Task #2

```shell
sudo tcpdump -w grehack.fr.pcap host grehack.fr and port 443

SLKEYLOGFILE=grehack.fr.keys.log curl --tls-max 1.2 https://grehack.fr

editcap --inject-secrets tls,grehack.fr.keys.log grehack.fr.pcap grehack.fr.pcapng
```

```python
>>> load_layer("tls")

>>> l = rdpcap("grehack.fr.pcapng")
>>> conf.tls_session_enable = True

>>> [p for p in l if TLS in p and p[TLS].type == 23]
[<Ether  dst=00:1c:42:00:00:18 src=00:1c:42:4c:9c:6c type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=143 id=23763 flags=DF frag=0 ttl=64 proto=tcp chksum=0xe9b0 src=10.211.55.4 dst=137.74.40.196 |<TCP  sport=40532 dport=https seq=303795701 ack=433210934 dataofs=5 reserved=0 flags=PA window=501 chksum=0xf466 urgptr=0 |<TLS  type=application_data version=TLS 1.2 len=98    [deciphered_len= 74] iv=b'\xe8\xef^\xc4\xf1\x93\x06\x06' msg=[<TLSApplicationData  data='GET / HTTP/1.1\r\nHost: grehack.fr\r\nUser-Agent: curl/7.74.0\r\nAccept: */*\r\n\r\n' |>] mac=b'\xfdW&\x98.\xcfxRm\xf9\x90b\xca\xf3\x82\xb8' padlen=None |>>>>, <Ether  dst=00:1c:42:4c:9c:6c src=00:1c:42:00:00:18 type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=1500 id=59987 flags= frag=0 ttl=128 proto=tcp chksum=0x56e3 src=137.74.40.196 dst=10.211.55.4 |<TCP  sport=https dport=40532 seq=433210934 ack=303795804 dataofs=5 reserved=0 flags=PA window=16384 chksum=0xd341 urgptr=0 |<TLS  type=application_data version=TLS 1.2 len=2737    [deciphered_len= 1431] iv=b'\xb5\xb6w}\x8c\xe5\x92\xb0' msg=[<TLSApplicationData  data='HTTP/1.1 200 OK\r\nServer: nginx/1.10.3\r\nDate: Thu, 18 Nov 2021 11:31:36 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 2520\r\nConnection: keep-alive\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE html>\n<html>\n\n<head>\n\t<title>Ethical hacking conference and Capture the flag in Grenoble</title>\n\t<meta http-equiv="Content-type" content="text/html" charset="UTF-8">\n\t<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">\n\t<link href="/static/_2021/css/grehack.css" rel="stylesheet">\n\t<link media="screen and (min-width: 600px)" href="/static/_2021/css/grehack_wide.css" rel="stylesheet">\n\t<link rel="shortcut icon" type="image/x-icon" href="/static/_2021/img/favicon.ico">\n\t\n\t\n\t\n</head>\n\n<body>\n\n<img class="banner" src="/static/_2021/img/gh21_header.png" alt="GreHack 9th edition"/>\n\n<nav class="navbar">\n  <div class="navrow">\n    <a class="navtab" href="/2021/">Home</a>\n    <a class="navtab" href="/2021/info">Info</a>\n    <a class="navtab" href="/2021/program">Program</a>\n    <a class="navtab" href="/2021/sponsors">Sponsors</a>\n    <a class="navtab" href="/2021/workshops">Workshops</a>\n    <a class="navtab" href="/2021/ctf">CTF</a>\n  </div>\n</nav>\n\n<hr class="dash"/>\n\n<main>\n\n<h1>Save the date for GreHack 2021</h1>\n<p class="lead">\n    The 9<sup>th</sup> edition of GreHack will hold on <strong>November 19<sup>th</sup>, 2021</strong> and will be online.\n</p>\n<h2>Workshops registrat' |>] mac=b'Y~\xe8>p\xf8e\xca\x92t\xa2T\x8fkp\xbe' padlen=None |>>>>]
```

## Trophy 8 - Adding a New Protocol

```python
class GreHack(Packet):
    name = "GreHack Packet"
    fields_desc = [ ByteField("id", 0),
                    ByteEnumField("type", 0, { 0: "Guess", "1": "Reply", "2": "Trophy"}),
                    IntField("value", 0)
                  ]

    def hashret(self):
        return b"%c" % self.id

    def answers(self, other):
        return self.id == other.id and ((self.type == 1 and other.type == 0) or (self.type == 2 and other.type == 0))


bind_layers(UDP, GreHack, dport=1811, sport=1811)
```

## Trophy 9 - Answering Machines

### Task #1

```python
# You might need to specify the interface using the iface argument
>>> farpd(IP_addr="192.168.1.100", ARP_addr="00:01:02:03:04:05")

# In another Scapy shell
>>> arping("192.168.1.100/32")
```

### Task #2

The code looks like:

```python
    def is_request(self, req):
        return isinstance(req, GreHack) and req[GreHack].type == 1

    def make_reply(self, req):

        value = req[GreHack].value

        if value == 0x4242:
            answer = GreHack(type=3)
        elif value < 0x4242:
            answer = GreHack(type=2, value=0)
        else:
            answer = GreHack(type=2, value=1)

        return IP() / UDP() / answer
```

## Trophy 10 - Pipes Introduction

### Task #1

The code looks like:

```python
cs = ConsoleSink()
clf > cs
```

### Task #2

The code looks like:

```python
td = TransformDrain(transform_f)
clf > td
ijs = InjectSink()
td > ijs
```

### Task #3

The code looks like:

```python
ws = WrpcapSink("pipes.pcap")
td > ws
```
