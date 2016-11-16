# Guillaume Valadon <guillaume@valadon.net>

"""Template to a new protocol to Scapy"""

from scapy.all import *


class GreHack(TODO):
    name = "TODO"
    fields_desc = [ "TODO" ]

    def hashret(self):
        return "TODO"

    def answers(self, other):
        return "TODO"


if __name__ == "__main__":

    # Unit tests
    p1 = GreHack(type=1)
    p2 = GreHack(type=0)
    print p1.answers(p2)  # True
    print p1.answers(p1)  # False

    p3 = GreHack(type=2)
    print p3.answers(p2)  # True
    print p2.answers(p3)  # False

    p4 = IP(str(IP()/UDP()/GreHack()))
    print p4[UDP].sport == 1811  # True
