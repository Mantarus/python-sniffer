import socket
import sys
import itertools
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.tcp import TCP


def main():

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' + str(msg.errno) + ' Message ' + msg.strerror)
        sys.exit()

    for cnt in itertools.count():
        raw_data, addr = conn.recvfrom(65565)
        print('Receive packet #{} at {}'.format(str(cnt), str(addr[0])))
        eth = Ethernet(raw_data)

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)

            # TCP
            if ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                eth.print_header('')
                ipv4.print_header('')
                tcp.print_header('')
                print()

main()
