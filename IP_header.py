import socket
import struct

class IP_Header (object) :
    # constructor
    def __init__(self, source_addr, destination_addr, ip_data=""):
        self.__four_bit_version = 0b0100
        self.__internet_header_length = 0b0101     # at least 5
        self.__type_of_service = 0b00010000
        self.__total_len = 20 + 20      # max header len=60 bytes; min header len=20 bytes
        self.__identification = 0b0000000000000000 # uniquely identifies the datagram; usually increment by 1 each time a datagram is sent
        self.__flags = 0b000
        self.__fragment_offset = 0b0000000000000
        self.__time2live = 0b11111111              # upper limit of routers; usually 32/64; decrement each time; discared when TTL=0
        self.__protocol = socket.IPPROTO_TCP       # clearify upper layer protocol; TCP(6); UDP(17)
        self.__header_checksum = 2                 # filled by kernel
        self.__src_addr = socket.inet_aton(source_addr)
        self.__dest_addr = socket.inet_aton(destination_addr)
        #self.__options = ip_data
        #self.__padding = 0b00000000000000000000000000000000
    
    # privates
    def __checksum(self, ip_data):
        """checksum for ip data part"""
        sum_val = 0
        for i in range(0, len(ip_data), 2):
            sum_val += (ip_data[i] << 8) + (ip_data[i+1])
        sum_val = (sum_val >> 16) + (sum_val & 0xffff)
        sum_val = ~sum_val & 0xffff
        
        self.__header_checksum = sum_val;

    def __build_header(self):
        """build header"""
        version_IHL = (self.__four_bit_version << 4) + self.__internet_header_length
        flags_fragOffset = (self.__flags << 13) + self.__fragment_offset
        #tmp_header = struct.pack("!BBHHHBBH4s4s", version_IHL,
        #                               self.__type_of_service, self.__total_len,
        #                               self.__identification, flags_fragOffset,
        #                               self.__time2live, self.__protocol, self.__header_checksum,
        #                               self.__src_addr, self.__dest_addr)
        #self.__checksum(tmp_header)
        self.__ip_header = struct.pack("!BBHHHBBH4s4s", version_IHL,
                                       self.__type_of_service, self.__total_len,
                                       self.__identification, flags_fragOffset,
                                       self.__time2live, self.__protocol, self.__header_checksum,
                                       self.__src_addr, self.__dest_addr)
    #public
    def get_IP_header(self, src_addr, dest_addr):
        self.__src_addr = socket.inet_aton(src_addr)
        self.__dest_addr = socket.inet_aton(dest_addr)
        self.__build_header()
        return self.__ip_header