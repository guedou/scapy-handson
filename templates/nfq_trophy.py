# Guillaume Valadon <guillaume@valadon.net>

"""Template to use Scapy with NFQUEUE"""

# Note: the following command must be used before launching this script:
# sudo iptables -A OUTPUT -s 8.8.8.8 -p udp --sport 53 -j NFQUEUE --queue-num 2807

from scapy.all import *
import nfqueue
import socket

def scapy_callback(packet):
    # Get the data
    data = packet.get_data()

    # Accept the packet
    packet.set_verdict(nfqueue.NF_ACCEPT)  # NF_DROP is also valid


if __name__ == "__main__":
    # Get an NFQUEUE handler
    q = nfqueue.queue()

    # Set the callback
    q.set_callback(scapy_callback)

    # Open the queue and start parsing packets
    q.fast_open(2807, socket.AF_INET)
    q.try_run()
