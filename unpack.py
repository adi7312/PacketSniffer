import socket
import struct

def ethernet_frame(data):
    """Unpacking ethernet frame
    
    :param data: ethernet frame written in hexadecimal form
    :type data: tuple

    :returns: destination and source MAC address, coverted host's order to network order, data
    :rtype: tuple
    """
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(protocol), data[14:]


def get_mac_addr(bytes_of_addr):
    """Returning correct MAC address
    
    :param bytes_of_addr: byte array of MAC address
    :type bytes_of_addr: tuple

    :returns: MAC address in hexadecimal form (ie. AA:BB:CC:DD:EE:FF)
    :rtype: str
    """
    bytes_str = map('{:02x}'.format(), bytes_of_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def unpacking_ipv4(data):
    """Unpacks ipv4 header

    :param data: contains the IPv4 header and data
    :type data: tuple

    :returns: version, length of header, protocol, source and destination ipv4 address, 
    and rest of data (ie. information about TCP/UDP/...)
    :rtype: tuple
    """
    ver_header_len = data[0]
    ver = ver_header_len >> 4 # bitwise operator
    head_len = (ver_header_len & 15) * 4 # AND Operation
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ver, head_len, ttl, proto, ipv4(src), ipv4(target), data[head_len:]


def unpack_ICMP(data):
    """Unpacks ICMP header
    
    :param data: contains the ICMP header and data
    :type data: tuple

    :returns: type of ICMP, code, checksum and data
    :rtype: tuple
    """
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def unpack_TCP(data):
    """Unpacks TCP header
    
    :param data: contains the TCP header and data
    :type data: tuple

    :returns: source and destination port, sequence, acknowledgement and flags: URG, 
    ACK, PSH, RST, SYN, FIN and data
    :rtype: tuple
    """
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
    """Unpacks UDP header
    
    :param data: contains UDP header and data
    :type data: tuple

    :returns: source and destination port, size and data
    :rtype: tuple
    """
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def ipv4(addr):
    """Formating IPv4 into user-friendly record
    :param addr: IPv4 address in byte form
    :type addr: bytes

    :returns: user-friendly IPv4 (ie. 192.168.1.1)
    :rtype: str
    """
    return '.'.join(map(str, addr))


def format_lines(prefix, string, size=80):
    """Formating lines to make data part clearer

    :param prefix: prefix of every new line
    :type prefix: str

    :param string: string that will be formated
    :type string: str

    :param size: size of every line (default value: 80)
    :type size: int
    
    :returns: formated string
    :rtype: str
    """
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2 == 0:
            size -= 1
    return '\n'.join([prefix+line for line in textwrap.wrap(string,size)])