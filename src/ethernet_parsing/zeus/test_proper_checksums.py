#!/usr/bin/env python3
"""
Test with proper IP and TCP checksums
"""

import socket
import struct

def calculate_ip_checksum(header):
    """Calculate IP header checksum"""
    # Make sure checksum field is zero
    header_list = list(header)
    header_list[10:12] = [0, 0]  # Clear checksum field
    header = bytes(header_list)
    
    # Calculate checksum
    checksum = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i + 1]
        checksum += word
    
    # Add carry
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    
    # One's complement
    checksum = ~checksum & 0xFFFF
    return struct.pack('!H', checksum)

def calculate_tcp_checksum(src_ip, dst_ip, tcp_header):
    """Calculate TCP checksum with pseudo-header"""
    # Pseudo header
    pseudo_header = src_ip + dst_ip + b'\x00\x06' + struct.pack('!H', len(tcp_header))
    
    # Make sure TCP checksum field is zero
    tcp_list = list(tcp_header)
    tcp_list[16:18] = [0, 0]  # Clear checksum field
    tcp_header = bytes(tcp_list)
    
    # Combine pseudo header and TCP header
    data = pseudo_header + tcp_header
    
    # Pad to even length
    if len(data) % 2:
        data += b'\x00'
    
    # Calculate checksum
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    # Add carry
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    
    # One's complement
    checksum = ~checksum & 0xFFFF
    return struct.pack('!H', checksum)

def create_proper_tcp_syn():
    """Create TCP SYN with correct checksums"""
    # Ethernet header
    dst_mac = b'\x42\x30\xfe\xe9\x7c\x46'  # TAP MAC
    src_mac = b'\x00\x11\x22\x33\x44\x55'  # Source MAC
    ethertype = b'\x08\x00'  # IPv4
    
    # IP addresses
    src_ip = b'\x0A\x00\x00\x02'  # 10.0.0.2
    dst_ip = b'\x0A\x00\x00\x01'  # 10.0.0.1
    
    # IPv4 header (without checksum)
    ip_header = (
        b'\x45'        # Version 4, IHL 5
        b'\x00'        # TOS
        b'\x00\x28'    # Total length (40 bytes)
        b'\x12\x34'    # ID
        b'\x40\x00'    # Flags, Fragment offset
        b'\x40'        # TTL
        b'\x06'        # Protocol (TCP)
        b'\x00\x00'    # Checksum (will be calculated)
        + src_ip + dst_ip
    )
    
    # Calculate IP checksum
    ip_checksum = calculate_ip_checksum(ip_header)
    ip_header = ip_header[:10] + ip_checksum + ip_header[12:]
    
    # TCP header (without checksum)
    tcp_header = (
        b'\x80\x00'        # Source port 32768
        b'\x00\x50'        # Dest port 80
        b'\x00\x00\x00\x01' # Sequence number
        b'\x00\x00\x00\x00' # ACK number
        b'\x50\x02'        # Data offset 5, SYN flag
        b'\xFF\xFF'        # Window size
        b'\x00\x00'        # Checksum (will be calculated)
        b'\x00\x00'        # Urgent pointer
    )
    
    # Calculate TCP checksum
    tcp_checksum = calculate_tcp_checksum(src_ip, dst_ip, tcp_header)
    tcp_header = tcp_header[:16] + tcp_checksum + tcp_header[18:]
    
    # Complete frame
    frame = dst_mac + src_mac + ethertype + ip_header + tcp_header
    return frame

def test_proper_syn():
    """Test with proper checksums"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 7000))
        sock.settimeout(5.0)  # 5 second timeout
        
        frame = create_proper_tcp_syn()
        print(f"Sending TCP SYN with proper checksums ({len(frame)} bytes):")
        print(f"Frame: {frame.hex()}")
        
        sock.send(frame)
        
        try:
            response = sock.recv(1500)
            if response:
                print(f"Received response ({len(response)} bytes): {response.hex()}")
                
                # Parse ethernet header
                if len(response) >= 14:
                    ethertype = response[12:14]
                    if ethertype == b'\x08\x00':  # IPv4
                        print("IPv4 response detected!")
                        if len(response) >= 34:
                            protocol = response[23]
                            if protocol == 6:  # TCP
                                print("TCP response detected!")
                                if len(response) >= 54:
                                    flags = response[47]
                                    if flags & 0x12 == 0x12:  # SYN+ACK
                                        print("SUCCESS: Received TCP SYN-ACK!")
            else:
                print("No response received within timeout")
        except socket.timeout:
            print("Timeout waiting for response")
        
        sock.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_proper_syn()
