import socket
import sys
import struct

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = s.recvfrom(65536)
        dest_mac, src_mac, ethernet_protocol, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destnation: {dest_mac}, Source: {src_mac}, Protocol: {ethernet_protocol}')

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
    ttl, proto, src, targer = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ver, head_len, ttl, proto, ipv4(src), ipv4(targer), data[head_len:]


def ipv4(addr):
    return ':'.join(map(str, addr))

main()