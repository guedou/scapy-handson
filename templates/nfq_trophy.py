# Guillaume Valadon <guillaume@valadon.net>

"""
Template to use Scapy with NFQUEUE on Linux
"""

# Note: the following command must be used before launching this script:
# sudo iptables -I INPUT -s 8.8.8.8 -p udp --sport 53 -j NFQUEUE --queue-num 2807

from scapy.all import *
from netfilterqueue import NetfilterQueue
import socket


def scapy_callback(packet):
    # Get the data
    data = packet.get_payload()
    print(IP(data).summary())

    # Accept the packet
    packet.accept()


if __name__ == "__main__":
    # Get an NFQUEUE handler
    nfqueue = NetfilterQueue()

    # Set the callback
    nfqueue.bind(2807, scapy_callback)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass

    nfqueue.unbind()
