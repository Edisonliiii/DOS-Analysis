import socket
import struct
import IP_header

class TCP_Header (object):
    #constructor
    def __init__(self, src_ip, dest_ip, source, destination, seqNum, ackNum):
        # for psudo header
        # self.__psudo_ip_header;
        self.__psudo_src_ip = socket.inet_aton(src_ip);
        self.__psudo_dest_ip = socket.inet_aton(dest_ip);
        self.__psudo_reserve = 0;
        self.__psudo_protocol = socket.IPPROTO_TCP
        self.__psudo_total_len = 0;
        # TCP header options
        self.__src_port = source             # 2 bytes
        self.__dest_port = destination       # 2 ..
        self.__seq_num = seqNum              # 4 ..
        self.__ack_num = ackNum              # 4 ..
        self.__data_offset = (0b0000 << 4)   # 4 ..
        self.__reserved = 0b000
        #self.__NS = 0
        #self.__CWR = 0
        #self.__ECE = 1
        self.__URG = 0
        self.__ACK = 0
        self.__PSH = 0
        self.__RST = 0
        self.__SYN = 1
        self.__FIN = 0
        self.__window = socket.htons(5840)
        self.__tcp_checksum = 0
        self.__urgent_ptr = 0
        self.__options = 0b00000000
        #self.__padding = 0 #(0 << (32-self.__options.bit_length()))
        #self.__data = ""

    def __checksum(self, data):
        """checksum for ip data part"""
        sum_val = 0
        for i in range(0, len(data), 2):
            sum_val += (data[i] << 8) + (data[i+1])
        sum_val = (sum_val >> 16) + (sum_val & 0xffff)
        sum_val = ~sum_val & 0xffff
        
        self.__tcp_checksum = sum_val;

    def __build_header(self):
        # combine isolated sections
        offset_reserve = self.__data_offset + self.__reserved + self.__NS
        control_bits =   (self.__CWR << 7) + (self.__ECE << 6) \
                       + (self.__URG << 5) + (self.__ACK << 4) \
                       + (self.__PSH << 3) + (self.__RST << 2) \
                       + (self.__SYN << 1) + self.__FIN
        
        #option_field = self.__options + self.__padding    #has to be 32-bit

        # make header (psudo_ip + tcp_header + tcp_data)
        tmp_tcp_header = struct.pack("!HHLLBBHHH", self.__src_port, self.__dest_port,
                                     self.__seq_num, self.__ack_num, offset_reserve,
                                     control_bits, self.__window, self.__tcp_checksum,
                                     self.__urgent_ptr)

        self.__psudo_total_len = len(tmp_tcp_header)
        psudo_header = struct.pack("!4s4sBBH", self.__psudo_src_ip, self.__psudo_dest_ip,
                                   self.__psudo_reserve, self.__psudo_protocol, self.__psudo_total_len)
        tmp_tcp_segment = psudo_header + tmp_tcp_header

        # update the value of self.__tcp_checksum
        self.__checksum(tmp_tcp_segment)
        self.__psudo_total_len = len(tmp_tcp_segment)
        self.__tcp_segment = struct.pack("!HHLLBBHHH", self.__src_port, self.__dest_port,
                                         self.__seq_num, self.__ack_num, offset_reserve,
                                         control_bits, self.__window, self.__tcp_checksum,
                                         self.__urgent_ptr)

    # public
    def get_TCP_header(self, src_ip, dest_ip, source, destination):
        self.__psudo_src_ip = socket.inet_aton(src_ip)
        self.__psudo_dest_ip = socket.inet_aton(dest_ip)
        self.__src_port = source
        self.__dest_port = destination
        self.__build_header()
        return self.__tcp_segment

