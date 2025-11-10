#!/usr/bin/env python3
"""
Test TCP connectivity to both HTTP server (8080) and simple TCP server (9999)
"""
import socket
import struct
from scapy.all import Ether, IP, TCP, sendp

# Fixed MAC addresses from control script
BRIDGE_MAC = 'aa:bb:cc:dd:ee:ff'
DUT_MAC = '00:11:22:33:44:55'

def create_tcp_syn_frame(dst_ip, dst_port, src_port=32768):
    """Create a TCP SYN frame"""
    # Create Ethernet header
    eth_frame = Ether(
        dst=BRIDGE_MAC,     # Bridge MAC (destination) 
        src=DUT_MAC,        # DUT MAC (source)
        type=0x0800         # IPv4
    )
    
    # Create IP header
    ip_packet = IP(
        src="10.0.0.10",    # DUT IP
        dst=dst_ip,         # Target IP
        ttl=64,
        id=0x1234
    )
    
    # Create TCP header with SYN flag
    tcp_packet = TCP(
        sport=src_port,     # Source port
        dport=dst_port,     # Destination port  
        flags="S",          # SYN flag
        seq=1,              # Sequence number
        window=65535        # Window size
    )
    
    # Combine all layers
    frame = eth_frame / ip_packet / tcp_packet
    
    return bytes(frame)

def send_via_uart(frame, port_name):
    """Send frame via UART-over-TCP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 7000))
        
        print(f"📤 Sending TCP SYN to {port_name}...")
        print(f"Frame: {frame.hex()}")
        
        sock.send(frame)
        
        # Wait for response
        sock.settimeout(2.0)
        try:
            response = sock.recv(1024)
            print(f"✅ Response received for {port_name}: {response.hex()}")
        except socket.timeout:
            print(f"⏰ No response for {port_name}")
        
        sock.close()
        
    except Exception as e:
        print(f"❌ Error sending to {port_name}: {e}")

def main():
    """Test both TCP servers"""
    print("=== TCP Connectivity Test ===")
    
    # Test HTTP server on port 8080
    frame_8080 = create_tcp_syn_frame("10.0.0.2", 8080)
    send_via_uart(frame_8080, "HTTP server (8080)")
    
    print("\n" + "="*50 + "\n")
    
    # Test simple TCP server on port 9999
    frame_9999 = create_tcp_syn_frame("10.0.0.2", 9999)
    send_via_uart(frame_9999, "Simple TCP server (9999)")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main()
