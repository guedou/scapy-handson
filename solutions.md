# Scapy Hands-on at #GreHack20

This file contains possible solutions for the GreHack20 trophies!


## Trophy 1 - Manipulating Packets

**task #1**
```
>>> p = IP(dst="8.8.8.8") / UDP() / DNS(qd=DNSQR())

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

**task #2**
```
>>> p = IP(ttl=(1, 5)) / ICMP()

>>> [packet for packet in p]
[<IP  frag=0 ttl=1 proto=icmp |<ICMP  |>>, <IP  frag=0 ttl=2 proto=icmp |<ICMP |>>, <IP  frag=0 ttl=3 proto=icmp |<ICMP  |>>, <IP  frag=0 ttl=4 proto=icmp |<ICMP  |>>, <IP  frag=0 ttl=5 proto=icmp |<ICMP  |>>]
```


## Trophy 2 - Network Interactions

**task #1**
```
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

**task #2**
```
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

**task #3**
```
>>> srloop(IP(dst="8.8.8.8") / ICMP())
[.. truncated ..]

>>> srloop(IP(dst="8.8.8.8") / ICMP(), prn=lambda p: p[1].src)
[.. truncated ..]
```

**task #4**
```
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
```
$ dig @8.8.8.8 grehack.fr A
```

At the end, the callback is the following:
```
def scapy_callback(packet):
    # Get the data
    data = packet.get_data()

    # Parse the DNS packet with Scapy
    p = IP(data)
    # Check if it contains a DNS header
    if p.getlayer(DNS):
        # Remove checksums and lengths
        del(p[IP].chksum, p[IP].len, p[UDP].chksum, p[UDP].len)

        # Iterate over the received DNS Resource Records
        tmp_dns_an = p[DNS].an
        while tmp_dns_an:
            # Identify the grehack.fr address and change it to 127.0.0.1
            if tmp_dns_an.rrname == "grehack.fr." and tmp_dns_an.type == 1:  # 'A' DNS query
                tmp_dns_an.rdata = "127.0.0.1"
                break
            tmp_dns_an = tmp_dns_an.payload

        # Rebuild the packet
        s = raw(p)
        # Set the verdict and return the new packet
        packet.set_verdict_modified(nfqueue.NF_ACCEPT, s, len(s))
             
    # Accept the packet
    packet.set_verdict(nfqueue.NF_ACCEPT)  # NF_DROP is also valid
```


## Trophy 4 - IPv6 Reconnaissance

**task #1**
```
>>> p = IPv6() / ICMPv6ND_RS()

>>> r = sr1(p)
```

**task #2**
```
>>> p = IPv6(dst="ff02::1") / ICMPv6EchoRequest()

>>> conf.checkIPsrc = False

>>> r = sr1(p)
```

**task #3**
```
>>> conf.checkIPsrc = False

>>> p = IPv6(dst="ff02::1") / ICMPv6EchoRequest()

>>> srloop(p, multi=1, prn=lambda sr: sr[1][IPv6].src)
```


## Trophy 5 - Visualizations

**task #1**
```
>>> p = IPv6() / ICMPv6EchoRequest()

>>> raw(p)

>>> hexdump(p)

>>> p.show()
>>> p.show2()

>>> p.pdfdump()  # set conf.prog.pdfreader to a valid program on your installation
```

**task #2**
```
>>> ans, unans = srloop(IP(dst=["8.8.8.8", "8.8.4.4"]) / ICMP(), inter=.1, timeout=.1, count=100, verbose=False)

>>> ans.multiplot(lambda sr: (sr[1][IP].src, (sr[1].time, sr[1][IP].id)), plot_xy=True)
```

**task #3**
```
>>> ans, unans = traceroute("www.wide.ad.jp", maxttl=15)

>>> ans.world_trace()
```


## Trophy 6 - Fun With X.509 Certificates

You might need to install the python `ecdsa` plugin to enable Certificate
manipulation tools.

**task #1**
```
>>> load_layer("tls")

>>> der_str = open("grehack.fr.der", "rb").read()
>>> pem_str = der2pem(der_str, obj="CERTIFICATE")
>>> open("grehack.fr.pem", "w").write(pem_str)

# If you could only retrive the certificate as PEM
>>> pem_str = open("grehack.fr.pem").read()
>>> der_str = pem2der(bytes(pem_str, "ascii"))

>>> c = X509_Cert(der_str)

>>> c.signatureValue
<ASN1_BIT_STRING['\x13\x18\x14\xa6e\x9b\xfa,\x9b\xd6...\xe9\x8b&\xc2\x94\xac|%\xe9h'] (0 unused bit)>

>>> c.tbsCertificate.subject
[<X509_RDN  rdn=[<X509_AttributeTypeAndValue  type=<ASN1_OID['commonName']> value=<ASN1_PRINTABLE_STRING['grehack.fr']> |>] |>]

>>> [e.extnValue for e in c.tbsCertificate.extensions if type(e.extnValue) == X509_ExtAuthInfoAccess]
[<X509_ExtAuthInfoAccess  authorityInfoAccess=[<X509_AccessDescription accessMethod=<ASN1_OID['ocsp']> accessLocation=<X509_GeneralName generalName=<X509_URI uniformResourceIdentifier=<ASN1_IA5_STRING['http://ocsp.int-x3.letsencrypt.org']> |> |> |>, <X509_AccessDescription  accessMethod=<ASN1_OID['caIssuers']> accessLocation=<X509_GeneralName  generalName=<X509_URI uniformResourceIdentifier=<ASN1_IA5_STRING['http://cert.int-x3.letsencrypt.org/']> |> |> |>] |>]
```

Check the content of the PEM file with:
```
$ openssl x509 -noout -text -in grehack.fr.pem
```

**task #2**
```
>>> c = Cert("grehack.fr.der")

>>> c.remainingDays()
64.64104166666667

>>> c.isSelfSigned()
False
```
pen("new_cert.pem", "w").write(der2pem(str(new_cert), obj="CERTIFICATE"))

**task #3**

Generate a RSA private key with:
```
$ openssl genrsa -out priv.key
```

```
>>> pk = PrivKey("priv.key")
>>> c = Cert("grehack.fr.der")
>>> c.tbsCertificate.serialNumber = 0x2807

>>> new_cert = pk.resignCert(c.x509Cert)
>>> open("new_cert.pem", "bw").write(der2pem(raw(new_cert), obj="CERTIFICATE"))

>>> pk.verifyCert(new_cert)
True
```

```
$ openssl x509 -noout -text -in new_cert.pem |grep -i serial
        Serial Number: 10247 (0x2807)
```


## Trophy 7 - Playing With TLS

**task #1**
```
>>> s = sniff(filter="tcp port 443")

>>> filtered = [x for x in s if TLS in x]

>>> ch = [p for p in filtered if TLSClientHello in p]

>>> ch[0][TLS].msg[0].ciphers
[43690,
 49195,
 49199,
 49196,
 49200,
 52393,
 52392,
 49171,
 49172,
 156,
 157,
 47,
 53,
 10]
```


## Trophy 8 - Adding a New Protocol

```
class GreHack(Packet):
    name = "GreHAck 2017"
    fields_desc = [ ByteField("id", 0),
                    ByteEnumField("type", 0, { 0: "Guess", "1": "Reply", "2": "Trophy"}),
                    IntField("value", 0)
                  ]

    def hashret(self):
        return "%c" % self.id

    def answers(self, other):
        return self.id == other.id and ((self.type == 1 and other.type == 0) or (self.type == 2 and other.type == 0))


bind_layers(UDP, GreHack, dport=1811, sport=1811)
```


## Trophy 9 - Answering Machines

**task #1**

```
# You might need to specify the interface using the iface argument
>>> farpd(IP_addr="192.168.1.100", ARP_addr="00:01:02:03:04:05")

# In another Scapy shell
>>> arping("192.168.1.100/32")
```

**task #2**

The code looks like:
```
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

**task #1**

The code looks like:
```
cs = ConsoleSink()
clf > cs
```

**task #2**

The code looks like:
```
td = TransformDrain(transform_f)
clf > td
ijs = InjectSink()
td > ijs
```

**task #3**

The code looks like:
```
ws = WrpcapSink("pipes.pcap")
td > ws
```
