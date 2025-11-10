#!/usr/bin/env python3
"""
Debug script to test TAP interface connectivity step by step.
"""

import socket
import struct
import subprocess
import time

def test_ping_bridge():
    """Test if we can ping the bridge IP"""
    print("🔍 Testing ping to bridge IP 10.0.0.1...")
    result = subprocess.run(['ping', '-c', '3', '10.0.0.1'], 
                          capture_output=True, text=True)
    if result.returncode == 0:
        print("✅ Bridge 10.0.0.1 is reachable")
        return True
    else:
        print(f"❌ Bridge ping failed: {result.stderr}")
        return False

def test_ping_http_ip():
    """Test if we can ping the HTTP server IP"""
    print("🔍 Testing ping to HTTP server IP 10.0.0.2...")
    result = subprocess.run(['ping', '-c', '3', '10.0.0.2'], 
                          capture_output=True, text=True)
    if result.returncode == 0:
        print("✅ HTTP server IP 10.0.0.2 is reachable")
        return True
    else:
        print(f"❌ HTTP server IP ping failed: {result.stderr}")
        return False

def test_http_server():
    """Test if we can start a simple HTTP server"""
    print("🔍 Testing HTTP server on 10.0.0.2:8080...")
    try:
        # Start a simple HTTP server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('10.0.0.2', 8080))
        server.listen(1)
        server.settimeout(1.0)
        
        print("✅ HTTP server started successfully")
        
        # Try to connect from localhost
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(('10.0.0.2', 8080))
        client.send(b'GET / HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n')
        
        print("✅ HTTP client connection successful")
        
        # Accept the connection
        conn, addr = server.accept()
        data = conn.recv(1024)
        print(f"✅ HTTP server received: {data[:50]}...")
        
        # Send response
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
        conn.send(response)
        
        conn.close()
        client.close()
        server.close()
        
        print("✅ HTTP server test completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ HTTP server test failed: {e}")
        try:
            server.close()
        except:
            pass
        return False

def create_test_ethernet_frame():
    """Create a test ethernet frame for HTTP request to 10.0.0.2:8080"""
    
    # Ethernet header
    dst_mac = bytes.fromhex('2e:c6:b0:7a:e9:6a'.replace(':', ''))  # Bridge MAC from ip addr
    src_mac = bytes.fromhex('00:11:22:33:44:55')  # Fake DUT MAC
    ethertype = struct.pack('>H', 0x0800)  # IPv4
    
    # IP header
    ip_version_ihl = 0x45  # IPv4, 20 byte header
    ip_tos = 0
    ip_len = struct.pack('>H', 60)  # Total length (20 IP + 20 TCP + 20 data)
    ip_id = struct.pack('>H', 12345)
    ip_flags_frag = struct.pack('>H', 0x4000)  # Don't fragment
    ip_ttl = 64
    ip_proto = 6  # TCP
    ip_checksum = struct.pack('>H', 0)  # Will calculate later
    ip_src = socket.inet_aton('192.168.1.100')  # Fake DUT IP
    ip_dst = socket.inet_aton('10.0.0.2')  # HTTP server IP
    
    # TCP header (simplified)
    tcp_src_port = struct.pack('>H', 12345)
    tcp_dst_port = struct.pack('>H', 8080)
    tcp_seq = struct.pack('>I', 100)
    tcp_ack = struct.pack('>I', 0)
    tcp_flags = struct.pack('>H', 0x5002)  # SYN flag, 20 byte header
    tcp_window = struct.pack('>H', 65535)
    tcp_checksum = struct.pack('>H', 0)  # Will calculate later
    tcp_urgent = struct.pack('>H', 0)
    
    # Assemble frame
    ip_header = (bytes([ip_version_ihl, ip_tos]) + ip_len + ip_id + 
                ip_flags_frag + bytes([ip_ttl, ip_proto]) + ip_checksum + 
                ip_src + ip_dst)
    
    tcp_header = (tcp_src_port + tcp_dst_port + tcp_seq + tcp_ack + 
                 tcp_flags + tcp_window + tcp_checksum + tcp_urgent)
    
    ethernet_frame = dst_mac + src_mac + ethertype + ip_header + tcp_header
    
    return ethernet_frame

def main():
    print("🚀 TAP Interface Debug Test")
    print("=" * 50)
    
    # Step 1: Test bridge connectivity
    if not test_ping_bridge():
        print("❌ Bridge connectivity failed - check TAP/bridge setup")
        return
    
    # Step 2: Test HTTP server IP connectivity  
    if not test_ping_http_ip():
        print("❌ HTTP server IP not reachable")
        return
    
    # Step 3: Test HTTP server functionality
    if not test_http_server():
        print("❌ HTTP server test failed")
        return
    
    # Step 4: Create test ethernet frame
    print("🔍 Creating test ethernet frame...")
    frame = create_test_ethernet_frame()
    print(f"✅ Created {len(frame)} byte ethernet frame: {frame[:32].hex()}...")
    
    print("\n🎉 All tests passed! TAP interface should work with your DUT.")
    print("Now you can run the control.py script and it should handle ethernet frames properly.")

if __name__ == "__main__":
    main()
