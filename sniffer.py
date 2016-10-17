# Packet sniffer in python
# For Linux

import socket

# create an INET, raw socket
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# receive a packet
while True:
    print(conn.recvfrom(65565))
    print()