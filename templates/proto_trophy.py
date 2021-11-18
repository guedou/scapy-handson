# Guillaume Valadon <guillaume@valadon.net>

"""
Template to add a new protocol to Scapy
"""

from scapy.all import *


class GreHack(TODO):
    name = "TODO"
    fields_desc = ["TODO"]

    def hashret(self):
        return "TODO"

    def answers(self, other):
        return "TODO"


if __name__ == "__main__":
    # Unit tests
    p1 = GreHack(type=1)
    p2 = GreHack(type=0)
    assert(p1.answers(p2))
    assert(p1.answers(p1) is False)

    p3 = GreHack(type=2)
    assert(p3.answers(p2))
    assert(p2.answers(p3) is False)

    p4 = IP(raw(IP() / UDP() / GreHack()))
    assert(p4[UDP].sport == 1811)
