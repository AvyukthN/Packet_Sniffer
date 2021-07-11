import socket
import struct
import textwrap

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
    addr_string = map('{:02X}'.format(addr_bytes))

    return ':'.join(addr_string)

if __name__ == '__main__':
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
        protocol = e_frame_hash['protocol']
        payload = e_frame_hash['PAYLOAD']

        print('\nEthernet FRAME')
        print('\n\tDestination {}\n\tSource {}\n\tProtocol {}'.format(mac_addr, src_addr, protocol))

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