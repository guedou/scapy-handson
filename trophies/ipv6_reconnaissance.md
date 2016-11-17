# IPv6 reconnaissance

This trophy provides you some simple tricks to perform IPv6 reconnaissances with
Scapy.

## Tasks

**task #1**

- build a simple IPv6 packet with a Router Solicitation (RS) packet on top
- send it with sr1
- do you have an answer ?


**task #2**

- build a simple IPv6 `ping6` packet to ff0::1 (i.e. all nodes)
- set the `conf.checkIPsrc` variable to False
- send it with sr1
- do you have an answer ?


**task #3**

- use `srloop` to send the previously built message, using the `multi` argument
- do you have many answers ?
- stop it
- add a `prn` argument to display all received IPv6 source addresses


## Hints

- all IPv6 related layers start with **IPv6** or **ICMP6**: use TAB !
