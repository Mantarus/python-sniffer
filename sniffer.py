import socket
import sys
import itertools
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.tcp import TCP
from networking.vnc import *


def main():

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' + str(msg.errno) + ' Message ' + msg.strerror)
        sys.exit()

    for cnt in itertools.count():
        raw_data, addr = conn.recvfrom(65565)
        packet = []
        print('Receive packet #{} at {}'.format(str(cnt), str(addr[0])))
        eth = Ethernet(raw_data)
        packet.append(eth)

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            packet.append(ipv4)

            # TCP
            if ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                packet.append(tcp)

                if tcp.dest_port in VNC.ports or tcp.src_port in VNC.ports:
                    print('Probably VNC Packet!')
                if len(tcp.data) == 12:
                    vnc = VNCProtocolVersion(tcp.data)
                    packet.append(vnc)
                    for item in packet:
                        print(item)

                print()

main()
