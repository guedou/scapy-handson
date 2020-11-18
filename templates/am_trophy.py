# Guillaume Valadon <guillaume@valadon.net>

"""
Template to create a Scapy answering machine
"""

from scapy.all import *
from proto_trophy import *


class GreHack_am(AnsweringMachine):

    def is_request(self, req):
        return False

    def make_reply(self, req):
        return ""


if __name__ == "__main__":
    gam = GreHack_am()
    gam.run()
