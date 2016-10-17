# Packet sniffer in python
# For Linux

import socket
import sys

# create an INET, raw socket
try:
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except socket.error as msg:
    print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

# receive a packet
while True:
    print(conn.recvfrom(65565))
    print()