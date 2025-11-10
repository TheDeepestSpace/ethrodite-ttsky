#!/usr/bin/env python3
"""
Test to verify Ethernet II vs 802.3 frame interpretation
"""

import socket
import struct

def create_minimal_tcp_syn():
    """Create minimal but valid Ethernet II frame"""
    # Ethernet header
    dst_mac = b'\x42\x30\xfe\xe9\x7c\x46'  # TAP MAC
    src_mac = b'\x00\x11\x22\x33\x44\x55'  # Source MAC
    ethertype = b'\x08\x00'  # IPv4 (0x0800 = 2048, > 1500 so it's EtherType)
    
    # Build IPv4 header manually to avoid struct issues
    ip_header = (
        b'\x45'           # Version=4, IHL=5
        b'\x00'           # TOS
        b'\x00\x28'       # Total length (40 bytes)
        b'\x12\x34'       # ID
        b'\x40\x00'       # Flags=don't fragment
        b'\x40'           # TTL=64
        b'\x06'           # Protocol=TCP
        b'\x00\x00'       # Checksum (will calculate)
        b'\x0a\x00\x00\x02'  # Src IP 10.0.0.2
        b'\x0a\x00\x00\x01'  # Dst IP 10.0.0.1
    )
    
    # Calculate IP checksum
    def calc_checksum(data):
        if len(data) % 2:
            data += b'\x00'
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        return ~checksum & 0xFFFF
    
    # Update IP header with correct checksum
    ip_checksum = calc_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]
    
    # Build TCP header manually
    tcp_header = (
        b'\x80\x00'       # Source port 32768
        b'\x00\x50'       # Destination port 80
        b'\x00\x00\x00\x01'  # Sequence number
        b'\x00\x00\x00\x00'  # ACK number
        b'\x50\x02'       # Data offset=5, SYN flag
        b'\xFF\xFF'       # Window size
        b'\x00\x00'       # Checksum (will calculate)
        b'\x00\x00'       # Urgent pointer
    )
    
    # Build pseudo-header for TCP checksum
    pseudo_header = (
        b'\x0a\x00\x00\x02'  # Src IP
        b'\x0a\x00\x00\x01'  # Dst IP
        b'\x00\x06'          # Reserved + Protocol
        b'\x00\x14'          # TCP length (20)
    )
    
    tcp_checksum = calc_checksum(pseudo_header + tcp_header)
    tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
    
    # Complete frame
    frame = dst_mac + src_mac + ethertype + ip_header + tcp_header
    return frame

def test_ethernet_ii():
    """Test with proper Ethernet II frame"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 7000))
        sock.settimeout(3.0)
        
        frame = create_minimal_tcp_syn()
        print(f"Sending Ethernet II frame ({len(frame)} bytes)")
        print(f"Frame: {frame.hex()}")
        
        # Show frame structure
        print(f"Dst MAC: {frame[0:6].hex(':')}")
        print(f"Src MAC: {frame[6:12].hex(':')}")  
        print(f"EtherType: 0x{frame[12:14].hex()} (should be > 1500 for Ethernet II)")
        print(f"Payload length: {len(frame) - 14} bytes")
        
        sock.send(frame)
        
        try:
            response = sock.recv(1500)
            if response:
                print(f"SUCCESS: Received response ({len(response)} bytes)")
                
                # Check if it's an IPv4 response
                if len(response) >= 14 and response[12:14] == b'\x08\x00':
                    print("IPv4 response detected!")
                    if len(response) >= 34 and response[23] == 6:  # TCP
                        print("TCP response detected!")
                        if len(response) >= 54:
                            tcp_flags = response[47]
                            if tcp_flags & 0x12 == 0x12:  # SYN+ACK
                                print("🎉 SUCCESS: Received TCP SYN-ACK response!")
                            elif tcp_flags & 0x04:  # RST
                                print("Received TCP RST (connection refused)")
                            else:
                                print(f"TCP flags: 0x{tcp_flags:02x}")
                else:
                    print(f"Non-IPv4 response: {response.hex()}")
            else:
                print("No response received")
        except socket.timeout:
            print("Timeout - no response")
        
        sock.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_ethernet_ii()
