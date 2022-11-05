import socket
from unpack import *

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
            print(f'{TAB_2} Protocol: {proto}, Source: {src}, Target: {target}')

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
                (src_port, dest_port, length, data) = unpack_UDP(data)
                print(f'{TAB_1} UDP Segment:')
                print(f'{TAB_2} Source port: {src_port}, Destination port: {dest_port}, Length: {length}')
            
            # other
            else:
                print(f'{TAB_1} Data: ')
                print(format_lines(DATA_TAB_2, data))
main()