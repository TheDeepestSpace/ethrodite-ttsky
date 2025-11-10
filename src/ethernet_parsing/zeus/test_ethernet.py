#!/usr/bin/env python3
"""
Test script to send a mock ethernet frame over UART-TCP to test TAP integration.
"""

import socket
import time

def create_mock_ethernet_frame():
    """Create a simple ethernet frame for testing"""
    # Ethernet header (14 bytes)
    dst_mac = b'\xFF\xFF\xFF\xFF\xFF\xFF'  # Broadcast MAC
    src_mac = b'\x00\x11\x22\x33\x44\x55'  # Source MAC  
    ethertype = b'\x08\x00'                # IPv4
    
    # Simple IPv4 header (20 bytes minimum)
    version_ihl = b'\x45'      # Version 4, IHL 5 (20 bytes)
    tos = b'\x00'              # Type of Service
    total_length = b'\x00\x2E' # Total Length (46 bytes)
    identification = b'\x12\x34'
    flags_fragment = b'\x40\x00'  # Don't fragment
    ttl = b'\x40'              # TTL 64
    protocol = b'\x06'         # TCP
    checksum = b'\x00\x00'     # Will be wrong, but for testing
    src_ip = b'\x0A\x00\x00\x02'  # 10.0.0.2
    dst_ip = b'\x0A\x00\x00\x01'  # 10.0.0.1
    
    # Simple TCP header (20 bytes minimum)
    src_port = b'\x80\x00'     # Port 32768
    dst_port = b'\x00\x50'     # Port 80 (HTTP)
    seq_num = b'\x00\x00\x00\x01'
    ack_num = b'\x00\x00\x00\x00'
    flags = b'\x50\x02'        # SYN flag
    window = b'\xFF\xFF'
    tcp_checksum = b'\x00\x00'
    urgent = b'\x00\x00'
    
    # Combine all parts
    ethernet_header = dst_mac + src_mac + ethertype
    ip_header = (version_ihl + tos + total_length + identification + 
                flags_fragment + ttl + protocol + checksum + src_ip + dst_ip)
    tcp_header = (src_port + dst_port + seq_num + ack_num + 
                 flags + window + tcp_checksum + urgent)
    
    frame = ethernet_header + ip_header + tcp_header
    return frame

def send_ethernet_frame():
    """Send ethernet frame over UART-TCP"""
    try:
        # Connect to UART server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 7000))
        
        # Create and send mock ethernet frame
        frame = create_mock_ethernet_frame()
        print(f"Sending ethernet frame ({len(frame)} bytes): {frame.hex()}")
        
        sock.send(frame)
        
        # Wait for ACK
        ack = sock.recv(1)
        print(f"Received ACK: {ack.hex()}")
        
        sock.close()
        print("Frame sent successfully!")
        
    except Exception as e:
        print(f"Error sending frame: {e}")

if __name__ == "__main__":
    send_ethernet_frame()
