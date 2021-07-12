import socket
import struct
import textwrap
import requests
from requests.api import head

IPV4_PROTOCOL = 8
TCP_PROTOCOL  = 6
UDP_PROTOCOL  = 17
ICMP_PROTOCOL = 1

# parses the ethernet frame
def parse_ethernet_frame(packet):
    # struct converts data to and from bytes format
    # ! says that were dealing with network data (cuz network data and data stored on comp r diff)
    # convert from Big Indian to Little Indian
    # only looking at first 14 bytes of packet that we sniffed
    # 6s (6) + 6s (6) + H (2) = 6 + 6 + 2 = 14

    # destination 6s - 6 chars/bytes
    # source      6s - 6 chars/bytes
    # H           small unsigned int
    # Reciever, Sender, Protocol Type (from ethernet packet)

    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', packet[:14])
    # packet[14:] (the rest of ethernet packet) will be the PAYLOAD in ethernet frame
    # [14:] because we don't know how big the PAYLOAD will be (could be an image, audio file, text message etc.)

    # mac_addr_ex is a helper function that extracts mac address from the weirdly formatted data that we parsed from ethernet frame
    # socket.htons will take bytes from ethernet packet and make compatable with ur computer so we can read it (big indian vs little indian)
    parsed_e_frame = {'destination_address' : mac_addr_ex(dest_mac),
                      'source_address'      : mac_addr_ex(src_mac),
                      'protocol'            : socket.htons(protocol),
                      'PAYLOAD'             : packet[14:]}

    return parsed_e_frame

# formats MAC address -- BYTES => AA:BB:CC:DD:EE:FF
def mac_addr_ex(addr_bytes):
    addr_string = map('{:02X}'.format, addr_bytes)

    return ':'.join(addr_string)

# parsing IPv4 packets
def parse_ipv4_packet(packet):
    # First byte is Version and IHL (Header Length)
    # need to bitshift to right by 4 bits so we can isolate version
    # header length tells us where the data starts (at end of header length the data starts)
    version_header_len = packet[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4

    # extract other information in IP header
    time_to_live, protocol, src_addr, target_addr = struct.unpack('! 8x B B 2x 4s 4s', packet[:20])

    IP_packet_hash = {
        'version'       : version,
        'header_length' : header_len,
        'TTL'           : time_to_live,
        'protocol'      : protocol,
        'source_address': ipv4_ex(src_addr),
        'target_address': ipv4_ex(target_addr),
        'PAYLOAD'       : packet[header_len:]
    }

    return IP_packet_hash

# formats address to IPv4
def ipv4_ex(addr):
    # taking all address chunks and map them to a string then put all chunk strings into a string seperated by .
    return '.'.join(map(str, addr))

# parses TCP packet
def parse_TCP(packet):
    # TCP packet is part of the IP packet
    # our data is the first 14 bytes

    # offset_res_flags is 16 bits
    # need to bitshift that by 12 to get offset and multiply by 4

    # flags execute 3 way handshake to establish a base connection (saying hello and goodbye to server)

    # sequence number keeps track of total bytes sent out by host
    # if a TCP packet has 2000 bytes, once it is sent out 2000 is added to the sequence number
    # acknowledgement number keeps track of total bytes recieved
    src_port, destination_port, sequence_num, ack_num, offset_res_flags = struct.unpack('! H H L L H', packet[:14])

    offset = (offset_res_flags >> 12) * 4
    urg_flag  = (offset_res_flags & 32) >> 5
    ack_flag  = (offset_res_flags & 16) >> 4
    pash_flag = (offset_res_flags & 8) >> 3
    rst_flag  = (offset_res_flags & 4) >> 2
    syn_flag  = (offset_res_flags & 2) >> 1
    fin_flag  =  offset_res_flags & 1

    TCP_packet_hash = {
        'source_port'     : src_port,
        'destination_port': destination_port,
        'sequence_num'    : sequence_num,
        'ack_num'         : ack_num,
        'offset'          : offset,
        'URG_FLAG'        : urg_flag,
        'ACK_FLAG'        : ack_flag,
        'PASH_FLAG'       : pash_flag,
        'RST_FLAG'        : rst_flag,
        'SYN_FLAG'        : syn_flag,
        'FIN_FLAG'        : fin_flag,
        'PAYLOAD'         : packet[offset:]
    }

    return TCP_packet_hash

# parses ICMP packet
def parse_ICMP(packet):
    # checksum is the sum of the "correct" digits in the data packet
    # type, code, and checksum are the first 4 bytes of the ICMP packet
    packet_type, code, checksum = struct.unpack('! B B H', packet[:4])

    ICMP_hash = {
        'packet_type': packet_type,
        'code'       : code,
        'checksum'   : checksum,
        'PAYLOAD'    : packet[4:]
    }

    return ICMP_hash

# parses UDP packet
def parse_UDP(packet):
    src_port, dest_port, size = struct.unpack('! H H 2x H', packet[:8])
    
    UDP_packet_hash = {
        'source_port'      : src_port,
        'destination_port' : dest_port,
        'packet_size'      : size
    }

    return UDP_packet_hash

if __name__ == '__main__':
    conv_endpoint = 'https://ben.akrin.com/ipv6_mac_address_to_link_local_converter/?mode=api&mac={}'

    # socket.AF_PACKET and socket.SOCK_RAW used together gives us 14 BIT ETHERNET FRAMES with a protocol headers like IPv4, IPv6 etc. and optionally a transport protocol like TCP and the PAYLOAD
    # socket.ntohs(3) makes sure the data is compatible with all computers (ie Big indian to Little Indian etc.)
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        # recieves data in form (raw_packet_data, address)
        # 65536 is buffer size (highest buffer size possible)
        # whenever socket gets data we store it in these two variables raw_packet and address
        raw_packet, address = connection.recvfrom(65536)

        e_frame_hash = parse_ethernet_frame(raw_packet)

        mac_addr = e_frame_hash['destination_address']
        src_addr = e_frame_hash['source_address']
        ethernet_protocol = e_frame_hash['protocol']
        payload = e_frame_hash['PAYLOAD']

        mac_ipv = requests.get(conv_endpoint.format(mac_addr)).text
        src_ipv = requests.get(conv_endpoint.format(src_addr)).text

        print('\nEthernet FRAME')
        print('\n\tDestination {}\tIPv6 {}\n\tSource      {}\tIPv6 {}\n\tProtocol    {}'.format(mac_addr, mac_ipv, src_addr, src_ipv, ethernet_protocol))

        if ethernet_protocol == IPV4_PROTOCOL:
            ipv4_hash = parse_ipv4_packet(payload)
            print('\n\n\t\tIPv4 Packet\n\t\t\tVersion           {}\n\t\t\tHeader_Length     {}\n\t\t\tTTL               {}\n\t\t\tProtocol          {}\n\t\t\tSource            {}\n\t\t\tTarget            {}'.format(ipv4_hash['version'], ipv4_hash['header_length'], ipv4_hash['TTL'], ipv4_hash['protocol'], ipv4_hash['source_address'], ipv4_hash['target_address']))

            if ipv4_hash['protocol'] == TCP_PROTOCOL:
                tcp_hash = parse_TCP(ipv4_hash['PAYLOAD'])
                print('\n\n\t\tTCP Segment\n\t\t\tSource_Port          {}\n\t\t\tDestination_Port     {}\n\t\t\tSequence             {}\n\t\t\tAcknowledgement      {}\n\t\t\tFLAGS\n\t\t\tURG {}\tACK {}\tPSH {}\tRST {}\tSYN {}\tFIN {}\n\t\t\tData\n\t\t\t{}'.format(tcp_hash['source_port'], tcp_hash['destination_port'], tcp_hash['sequence_num'], tcp_hash['ack_num'], tcp_hash['URG_FLAG'], tcp_hash['ACK_FLAG'], tcp_hash['PASH_FLAG'], tcp_hash['RST_FLAG'], tcp_hash['SYN_FLAG'], tcp_hash['FIN_FLAG'], tcp_hash['PAYLOAD']))
            elif ipv4_hash['protocol'] == ICMP_PROTOCOL:
                icmp_hash = parse_ICMP(ipv4_hash['PAYLOAD'])
                print('\n\n\t\t\tICMP Packet\n\t\t\tType {}\n\t\t\tCode {}\n\t\t\tChecksum {}\n\t\t\t\n\t\t\tData {}'.format(icmp_hash['packet_type'], icmp_hash['code'], icmp_hash['checksum'], icmp_hash['PAYLOAD']))
            elif ipv4_hash['protocol'] == UDP_PROTOCOL:
                udp_hash = parse_UDP(ipv4_hash['PAYLOAD'])
                print('\n\n\t\tUDP Packet\n\t\t\tSource Port {}\tDestination Port {}\n\t\t\tLength      {}'.format(udp_hash['source_port'], udp_hash['destination_port'], udp_hash['packet_size']))
            else:
                print('Data\n\t\t{}'.format(payload))

# HTTP request to website to get some content from it
# need to send HTTP request with IP packet (the IP of the server and the IP of your computer) so it sends the request to the server and server sends it to ur comp
# need to get data from ur comp to router
# HTTP request is wrapped up in IP packet (address, return address)
# IP packet wrapped up in Ethernet Frame
# Ethernet frame is used to talk to router

"""
ETHERNET FRAME STRUCTURE

Sync           8 byte              Makes sure computer and router are in sync (when they are sending and receiving packets)
Reciever       6 byte              Who's receiving data (Router or Comp)
Sender         6 byte              Who's sending data (Router or Comp)
Type           2 byte              Ethernet Type/Protocol (make sure were working with standard internet traffic) IP4, IP6, ARP Req/Res etc.
PAYLOAD        46 - 1500 byte      MAIN DATA inside payload
CRC            4 byte              Checks if data recieved properly

VISUALIZATION
         
         Ethernet Frame
 ________________________________
|                                |
|           IP Packet            |
|       __________________       |
|      |                  |      |
|      |     HTTP Req     |      |
|      |    __________    |      |
|      |   |          |   |      |
|      |   |   data   |   |      |
|      |   |          |   |      |
|      |   |__________|   |      |
|      |                  |      |
|      |__________________|      |
|                                |
|________________________________|
"""