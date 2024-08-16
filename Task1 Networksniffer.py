import socket
import struct
import textwrap

def create_socket():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    conn.bind(("eth0", 0))  # Bind to eth0 interface
    return conn

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def sniff(conn):
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        if eth_proto == 8:  
            (ttl, proto, src, target, data) = ipv4_packet(data)
            print(f'\t- IPv4 Packet: TTL: {ttl}, Protocol: {proto}, Source: {src}, Target: {target}')

            if proto == 1:  
                icmp_type, code, checksum, data = icmp_packet(data)
                print(f'\t- ICMP Packet: Type: {icmp_type}, Code: {code}, Checksum: {checksum}')

            elif proto == 6:  
                src_port, dest_port, sequence, acknowledgment, data = tcp_segment(data)
                print(f'\t- TCP Segment: Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'\t  Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'\t  Data:')
                print(format_multi_line('\t\t', data))

            elif proto == 17:  
                src_port, dest_port, length, data = udp_segment(data)
                print(f'\t- UDP Segment: Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')

if __name__ == "__main__":
    conn = create_socket()
    sniff(conn)
