import socket
import sys
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = s.recvfrom(65536)
        dest_mac, src_mac, ethernet_protocol, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destnation: {dest_mac}, Source: {src_mac}, Protocol: {ethernet_protocol}')

        # 8: IPv4
        if ethernet_protocol == 8:
            (ver, head_len, ttl, proto, src, target, data) = unpacking_ipv4(data)
            print(f'{TAB_1} IPv4 Packet:')
            print(f'{TAB_2} Version: {ver}, Header length: {head_len}, TTL: {ttl}')
            print(f'{TAB_2} Protocol: {proto}, Target: {target}')

            # ICMP
            if proto == 1:
                (icmp_type, code, checksum, data) = unpack_ICMP(data)
                print(f'{TAB_1} ICMP Packet:')
                print(f'{TAB_2} Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(f'{TAB_2} Data:')
                print(format_lines(DATA_TAB_3, data))
            
            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = unpack_TCP(data)
                print(f'{TAB_1} TCP Segment:')
                print(f'{TAB_2} Source Port: {src_port}, Destination POrt: {dest_port}')
                print(f'{TAB_2} Sequence: {sequence}, Acknowledgment: {acknowledgement}')
                print(f'{TAB_2} Flags:')
                print(f'{TAB_3} URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(f'{TAB_2} Data:')
                print(format_lines(DATA_TAB_3, data))
            
            # UDP
            elif proto == 17:
                src_port, dest_port, length = unpack_UDP(data)
                print(f'{TAB_1} UDP Segment:')
                print(f'{TAB_2} Source port: {src_port}, Destination port: {dest_port}, Length: {length}')
            
            else:
                print(f'{TAB_1} Data: ')
                print(format_lines(DATA_TAB_2, data))


def ethernet_frame(data):
    """Unpacking ethernet frame"""
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(protocol), data[14:]


def get_mac_addr(bytes_of_addr):
    """Returning correct MAC address"""
    bytes_str = map('{:02x}'.format, bytes_of_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def unpacking_ipv4(data):
    ver_header_len = data[0]
    ver = ver_header_len >> 4 # bitwise operator
    head_len = (ver_header_len & 15) * 4 # AND Operation
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ver, head_len, ttl, proto, ipv4(src), ipv4(target), data[head_len:]


def ipv4(addr):
    return ':'.join(map(str, addr))


def unpack_ICMP(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def unpack_TCP(data):
    (src_port, dest_port, sequence, acknowledgement, offest_reservered_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offest_reservered_flags>>12) * 4
    flag_urg = (offest_reservered_flags & 32) >> 5
    flag_ack = (offest_reservered_flags & 16) >> 4
    flag_psh = (offest_reservered_flags & 8) >> 3
    flag_rst = (offest_reservered_flags & 4) >> 2
    flag_syn = (offest_reservered_flags & 2) >> 1
    flag_fin = (offest_reservered_flags & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, \
    flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def unpack_UDP(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_lines(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2 == 0:
            size -= 1
    return '\n'.join([prefix+line for line in textwrap.wrap(string,size)])



main()