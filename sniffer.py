# Packet sniffer in python
# For Linux

import socket
import sys

# create an INET, raw socket
from struct import unpack

import itertools

try:
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except socket.error as msg:
    print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

# receive a packet
for cnt in itertools.count():
#while True:
    print("Recieve packet #" + str(cnt))

    packet = conn.recvfrom(65565)

    # packet string from tuple
    packet = packet[0]

    # take first 20 characters for the ip header
    ip_header = packet[0:20]

    # now unpack them :)
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);

    print("Version: " + str(version))
    print("IP Header Length: " + str(ihl))
    print("TTL: " + str(ttl))
    print("Protocol: " + str(protocol))
    print("Source Address: " + str(s_addr))
    print("Destination Address: " + str(d_addr))
    print()

    tcp_header = packet[iph_length:iph_length + 20]
    # now unpack them :)
    try:
        tcph = unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4

        print("Source port: " + str(source_port))
        print("Destination port: " + str(dest_port))
        print("Sequence Number: " + str(sequence))
        print("Acknowledgement: " + str(acknowledgement))
        print("TCP Header Length: " + str(tcph_length))
        print()

        h_size = iph_length + tcph_length * 4
        data_size = len(packet) - h_size

        # get data from the packet
        data = packet[h_size:]

        print("Data: " + str(data))
        print()
    except:
        data = packet[iph_length:]
        print("Data: " + str(data))
        print()