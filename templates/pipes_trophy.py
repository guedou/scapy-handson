# Guillaume Valadon <guillaume@valadon.net>

"""Template to play with Scapy pipes"""

from scapy.all import *


def transform_f(string):
    """Put a string on top of a packet"""
    return Ether()/IP(dst="8.8.8.8")/UDP()/Raw(string)


# Pipes objects
clf = CLIFeeder()

# Start the pipe engine
pe = PipeEngine(clf)
pe.start()

# Inject a string
clf.send("Hello GreHack !")

# Stop the pipe engine
pe.stop()
