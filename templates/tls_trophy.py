# Guillaume Valadon <guillaume@valadon.net>

"""Template to use Scapy to retrieve TLS X.509 certificate"""

from scapy.all import *
import socket

# Connect to grehack.fr on 443/tcp
sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sck.connect(("grehack.fr", 443))

# Send a ClientHello
# TODO

# Receive data
# TODO

# Display the ciphersuite selected by the server
# TODO

# Close the socket
sck.close()
