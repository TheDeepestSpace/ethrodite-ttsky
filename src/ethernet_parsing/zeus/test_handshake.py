#!/usr/bin/env python3
"""
Enhanced test script to send ethernet frame and wait for responses
"""

import socket
import time
import threading

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
    """Create a simple ICMP ping frame for testing"""
    # Ethernet header (14 bytes)
    # Use fixed MAC addresses from control.py constants
    dst_mac = b'\xaa\xbb\xcc\xdd\xee\xff'  # Fixed bridge MAC: aa:bb:cc:dd:ee:ff
    src_mac = b'\x00\x11\x22\x33\x44\x55'  # DUT's MAC address: 00:11:22:33:44:55
    ethertype = b'\x08\x00'                # IPv4
    
    # IPv4 header (20 bytes) - build without checksum first
    version_ihl = b'\x45'      # Version 4, IHL 5
    tos = b'\x00'              # Type of Service
    total_length = b'\x00\x1C' # Total Length (28 bytes = 20 IP + 8 ICMP)
    identification = b'\x12\x34'
    flags_fragment = b'\x40\x00'  # Don't fragment
    ttl = b'\x40'              # TTL 64
    protocol = b'\x01'         # ICMP
    src_ip = b'\x0A\x00\x00\x0A'  # 10.0.0.10 (DUT)
    dst_ip = b'\x0A\x00\x00\x02'  # 10.0.0.2 (HTTP server)
    
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
    icmp_seq = b'\x00\x01'     # Sequence 1
    
    icmp_header_no_checksum = icmp_type + icmp_code + b'\x00\x00' + icmp_id + icmp_seq
    icmp_checksum = calculate_checksum(icmp_header_no_checksum)
    icmp_header = icmp_type + icmp_code + icmp_checksum.to_bytes(2, 'big') + icmp_id + icmp_seq
    
    # Combine all parts
    ethernet_header = dst_mac + src_mac + ethertype
    frame = ethernet_header + ip_header + icmp_header
    return frame

def create_tcp_syn_frame():
    """Create a TCP SYN frame targeting the HTTP server with correct checksums"""
    # Ethernet header (14 bytes)
    # Use fixed MAC addresses from control.py constants
    dst_mac = b'\xaa\xbb\xcc\xdd\xee\xff'  # Fixed bridge MAC: aa:bb:cc:dd:ee:ff
    src_mac = b'\x00\x11\x22\x33\x44\x55'  # DUT's MAC address: 00:11:22:33:44:55
    ethertype = b'\x08\x00'                # IPv4
    
    # IPv4 header (20 bytes) - build without checksum first
    version_ihl = b'\x45'      # Version 4, IHL 5
    tos = b'\x00'              # Type of Service
    total_length = b'\x00\x28' # Total Length (40 bytes = 20 IP + 20 TCP)
    identification = b'\x12\x34'
    flags_fragment = b'\x40\x00'  # Don't fragment
    ttl = b'\x40'              # TTL 64
    protocol = b'\x06'         # TCP
    src_ip = b'\x0A\x00\x00\x0A'  # 10.0.0.10 (DUT - within bridge network)
    dst_ip = b'\x0A\x00\x00\x02'  # 10.0.0.2 (HTTP server)
    
    # Calculate IP checksum
    ip_header_no_checksum = (version_ihl + tos + total_length + identification + 
                            flags_fragment + ttl + protocol + b'\x00\x00' + src_ip + dst_ip)
    ip_checksum = calculate_checksum(ip_header_no_checksum)
    
    ip_header = (version_ihl + tos + total_length + identification + 
                flags_fragment + ttl + protocol + ip_checksum.to_bytes(2, 'big') + src_ip + dst_ip)
    
    # TCP header (20 bytes) - build without checksum first
    src_port = b'\x80\x00'     # Port 32768 (random high port)
    dst_port = b'\x1F\x90'     # Port 8080 (HTTP server from control.py)
    seq_num = b'\x00\x00\x00\x01'  # Initial sequence number
    ack_num = b'\x00\x00\x00\x00'  # No ACK yet
    flags = b'\x50\x02'        # Data offset 5, SYN flag
    window = b'\xFF\xFF'       # Window size
    urgent = b'\x00\x00'       # No urgent pointer
    
    tcp_header_no_checksum = (src_port + dst_port + seq_num + ack_num + 
                             flags + window + b'\x00\x00' + urgent)
    
    # Calculate TCP checksum with pseudo-header
    pseudo_header = src_ip + dst_ip + b'\x00\x06' + b'\x00\x14'  # protocol=6, TCP length=20
    tcp_checksum_data = pseudo_header + tcp_header_no_checksum
    tcp_checksum = calculate_checksum(tcp_checksum_data)
    
    tcp_header = (src_port + dst_port + seq_num + ack_num + 
                 flags + window + tcp_checksum.to_bytes(2, 'big') + urgent)
    
    # Combine all parts
    ethernet_header = dst_mac + src_mac + ethertype
    frame = ethernet_header + ip_header + tcp_header
    return frame

def listen_for_responses(sock):
    """Listen for responses from the server"""
    try:
        while True:
            response = sock.recv(1500)  # MTU size
            if not response:
                break
            print(f"Received response ({len(response)} bytes): {response.hex()}")
            
            # Parse basic ethernet frame info
            if len(response) >= 14:
                dst_mac = response[0:6].hex()
                src_mac = response[6:12].hex()
                ethertype = response[12:14].hex()
                print(f"  Ethernet: dst={dst_mac} src={src_mac} type={ethertype}")
                
                if ethertype == '0800' and len(response) >= 34:  # IPv4
                    protocol = response[23]
                    src_ip = '.'.join(str(b) for b in response[26:30])
                    dst_ip = '.'.join(str(b) for b in response[30:34])
                    print(f"  IPv4: {src_ip} -> {dst_ip} protocol={protocol}")
                    
                    if protocol == 6 and len(response) >= 54:  # TCP
                        src_port = int.from_bytes(response[34:36], 'big')
                        dst_port = int.from_bytes(response[36:38], 'big')
                        seq = int.from_bytes(response[38:42], 'big')
                        ack = int.from_bytes(response[42:46], 'big')
                        flags = response[47]
                        print(f"  TCP: {src_port} -> {dst_port} seq={seq} ack={ack} flags=0x{flags:02x}")
                        
    except Exception as e:
        print(f"Response listener error: {e}")

def test_icmp_ping():
    """Test ICMP ping to see if basic connectivity works"""
    try:
        # Connect to UART server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 7000))
        print("Connected to UART server")
        
        # Start response listener in background
        response_thread = threading.Thread(target=listen_for_responses, args=(sock,), daemon=True)
        response_thread.start()
        
        # Send ICMP ping frame
        ping_frame = create_icmp_ping_frame()
        print(f"Sending ICMP ping frame ({len(ping_frame)} bytes): {ping_frame.hex()}")
        sock.send(ping_frame)
        
        # Wait for response
        print("Waiting for ICMP response...")
        time.sleep(2)
        
        sock.close()
        print("ICMP test completed")
        
    except Exception as e:
        print(f"ICMP test error: {e}")

def test_tcp_handshake():
    """Test TCP handshake with the HTTP server"""
    try:
        # Connect to UART server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 7000))
        print("Connected to UART server")
        
        # Start response listener in background
        response_thread = threading.Thread(target=listen_for_responses, args=(sock,), daemon=True)
        response_thread.start()
        
        # Send TCP SYN frame
        syn_frame = create_tcp_syn_frame()
        print(f"Sending TCP SYN frame ({len(syn_frame)} bytes): {syn_frame.hex()}")
        sock.send(syn_frame)
        
        # Keep connection alive to receive responses
        print("Waiting for TCP responses... (press Ctrl+C to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        
        sock.close()
        print("TCP test completed")
        
    except Exception as e:
        print(f"TCP test error: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "icmp":
            print("Testing ICMP ping...")
            test_icmp_ping()
        elif sys.argv[1] == "tcp":
            print("Testing TCP handshake...")
            test_tcp_handshake()
        else:
            print("Usage: python test_handshake.py [icmp|tcp]")
    else:
        print("Running both tests...")
        print("\n=== Testing ICMP first ===")
        test_icmp_ping()
        time.sleep(1)
        print("\n=== Testing TCP ===")
        test_tcp_handshake()
