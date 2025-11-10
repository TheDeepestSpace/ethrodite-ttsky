#!/usr/bin/env python3
"""
Simple ICMP ping test to see if we can get any kernel response
"""

import socket
import struct
import time

def calculate_checksum(data):
    """Calculate Internet checksum"""
    if len(data) % 2:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return (~checksum) & 0xFFFF

def create_icmp_ping_frame():
    """Create an ICMP ping frame"""
    # Ethernet header
    dst_mac = b'\x42\x30\xfe\xe9\x7c\x46'  # TAP interface MAC
    src_mac = b'\x00\x11\x22\x33\x44\x55'  # Source MAC  
    ethertype = b'\x08\x00'                # IPv4
    
    # IPv4 header
    version_ihl = b'\x45'      # Version 4, IHL 5
    tos = b'\x00'              # Type of Service
    total_length = b'\x00\x1c' # Total Length (28 bytes = 20 IP + 8 ICMP)
    identification = b'\x12\x34'
    flags_fragment = b'\x40\x00'  # Don't fragment
    ttl = b'\x40'              # TTL 64
    protocol = b'\x01'         # ICMP
    src_ip = b'\xC0\xA8\x01\x0A'  # 192.168.1.10 (external)
    dst_ip = b'\x0A\x00\x00\x02'  # 10.0.0.2 (our server)
    
    # Calculate IP checksum
    ip_header_no_checksum = (version_ihl + tos + total_length + identification + 
                            flags_fragment + ttl + protocol + b'\x00\x00' + src_ip + dst_ip)
    ip_checksum = calculate_checksum(ip_header_no_checksum)
    
    ip_header = (version_ihl + tos + total_length + identification + 
                flags_fragment + ttl + protocol + ip_checksum.to_bytes(2, 'big') + src_ip + dst_ip)
    
    # ICMP header (8 bytes)
    icmp_type = b'\x08'        # Echo Request
    icmp_code = b'\x00'        # Code 0
    icmp_id = b'\x12\x34'      # ID
    icmp_seq = b'\x00\x01'     # Sequence
    
    icmp_header_no_checksum = icmp_type + icmp_code + b'\x00\x00' + icmp_id + icmp_seq
    icmp_checksum = calculate_checksum(icmp_header_no_checksum)
    
    icmp_header = icmp_type + icmp_code + icmp_checksum.to_bytes(2, 'big') + icmp_id + icmp_seq
    
    # Combine all parts
    frame = dst_mac + src_mac + ethertype + ip_header + icmp_header
    return frame

def main():
    try:
        # Connect to UART server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 7000))
        print("Connected to UART server")
        
        # Create and send ICMP ping frame
        frame = create_icmp_ping_frame()
        print(f"Sending ICMP ping frame ({len(frame)} bytes): {frame.hex()}")
        print(f"Ping: 192.168.1.10 -> 10.0.0.2 (should get ICMP reply)")
        sock.send(frame)
        
        print("Waiting for ICMP reply...")
        sock.settimeout(5.0)
        
        try:
            response = sock.recv(1024)
            if response:
                print(f"Received response ({len(response)} bytes): {response.hex()}")
                
                # Quick check if it's ICMP reply
                if len(response) >= 34 and response[23] == 1:  # ICMP protocol
                    if len(response) >= 35 and response[34] == 0:  # ICMP Echo Reply
                        print("🎉 SUCCESS! Received ICMP Echo Reply!")
                    else:
                        print(f"ICMP type: {response[34] if len(response) > 34 else 'unknown'}")
            else:
                print("No response received")
                
        except socket.timeout:
            print("Timeout - no ICMP reply received")
        
        sock.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
