#!/usr/bin/env python3
"""
Debug script to analyze what's actually being sent to TAP interface
"""

import socket

def analyze_frame():
    """Analyze the frame byte by byte"""
    # Your exact frame from the log
    frame_hex = "4230fee97c4600112233445508004500002812344000400600000a0000020a0000018000005000000001000000005002ffff00000000"
    frame_bytes = bytes.fromhex(frame_hex)
    
    print(f"Total frame length: {len(frame_bytes)} bytes")
    print(f"Raw frame: {frame_hex}")
    print()
    
    # Parse ethernet header
    if len(frame_bytes) >= 14:
        dst_mac = frame_bytes[0:6]
        src_mac = frame_bytes[6:12]
        ethertype = frame_bytes[12:14]
        
        print("Ethernet Header:")
        print(f"  Dst MAC: {dst_mac.hex(':')}")
        print(f"  Src MAC: {src_mac.hex(':')}")
        ipv4_type = b'\x08\x00'
        print(f"  EtherType: {ethertype.hex()} ({'IPv4' if ethertype == ipv4_type else 'Unknown'})")
        print()
        
        # Parse IP header
        if ethertype == b'\x08\x00' and len(frame_bytes) >= 34:
            ip_header = frame_bytes[14:34]
            version = (ip_header[0] >> 4) & 0xF
            ihl = ip_header[0] & 0xF
            protocol = ip_header[9]
            src_ip = '.'.join(str(b) for b in ip_header[12:16])
            dst_ip = '.'.join(str(b) for b in ip_header[16:20])
            
            print("IP Header:")
            print(f"  Version: {version}")
            print(f"  IHL: {ihl}")
            print(f"  Protocol: {protocol} ({'TCP' if protocol == 6 else 'Other'})")
            print(f"  Src IP: {src_ip}")
            print(f"  Dst IP: {dst_ip}")
            print()
            
            # Parse TCP header
            if protocol == 6 and len(frame_bytes) >= 54:
                tcp_header = frame_bytes[34:54]
                src_port = int.from_bytes(tcp_header[0:2], 'big')
                dst_port = int.from_bytes(tcp_header[2:4], 'big')
                seq_num = int.from_bytes(tcp_header[4:8], 'big')
                ack_num = int.from_bytes(tcp_header[8:12], 'big')
                flags = tcp_header[13]
                
                print("TCP Header:")
                print(f"  Src Port: {src_port}")
                print(f"  Dst Port: {dst_port}")
                print(f"  Seq: {seq_num}")
                print(f"  Ack: {ack_num}")
                print(f"  Flags: 0x{flags:02x} ({'SYN' if flags & 0x02 else ''})")
                print()
    
    # Show what tcpdump might be seeing incorrectly
    print("What tcpdump shows vs what it should show:")
    print(f"tcpdump sees: 44:55:08:00:45:00")
    print(f"Should see:")
    print(f"  Src MAC: 00:11:22:33:44:55")
    print(f"  EtherType: 08:00 (IPv4)")
    print(f"  IP Version: 4, Length: 40")

def send_debug_frame():
    """Send the frame and capture what happens"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 7000))
        
        # Create the exact same frame
        dst_mac = b'\x42\x30\xfe\xe9\x7c\x46'
        src_mac = b'\x00\x11\x22\x33\x44\x55'
        ethertype = b'\x08\x00'
        
        # Simple IP+TCP payload
        payload = bytes.fromhex("4500002812344000400600000a0000020a0000018000005000000001000000005002ffff00000000")
        
        frame = dst_mac + src_mac + ethertype + payload
        
        print(f"Sending frame: {frame.hex()}")
        print(f"Expected in tcpdump: src={src_mac.hex(':')} dst={dst_mac.hex(':')} type=0800")
        
        sock.send(frame)
        sock.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("=== Frame Analysis ===")
    analyze_frame()
    print("\n=== Sending Debug Frame ===")
    send_debug_frame()
