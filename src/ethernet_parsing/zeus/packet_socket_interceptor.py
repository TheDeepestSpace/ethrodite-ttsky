#!/usr/bin/env python3
"""
Packet socket TCP interceptor - intercepts at Ethernet level
This should work better than raw IP sockets for bridge traffic
"""
import socket
import struct
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_ethernet_frame(data):
    """Parse ethernet frame and extract TCP info if present"""
    try:
        if len(data) < 14:  # Minimum ethernet header
            return None
            
        # Parse ethernet header
        dst_mac = data[0:6].hex(':')
        src_mac = data[6:12].hex(':')
        ethertype = struct.unpack('>H', data[12:14])[0]
        
        if ethertype != 0x0800:  # Not IPv4
            return None
            
        # Parse IP header
        ip_start = 14
        if len(data) < ip_start + 20:  # Minimum IP header
            return None
            
        ip_data = data[ip_start:]
        version_ihl = ip_data[0]
        ihl = (version_ihl & 0xf) * 4
        protocol = ip_data[9]
        
        if protocol != 6:  # Not TCP
            return None
            
        src_ip = '.'.join(str(b) for b in ip_data[12:16])
        dst_ip = '.'.join(str(b) for b in ip_data[16:20])
        
        # Parse TCP header
        tcp_start = ip_start + ihl
        if len(data) < tcp_start + 20:  # Minimum TCP header
            return None
            
        tcp_data = data[tcp_start:]
        src_port, dst_port, seq, ack = struct.unpack('>HHLL', tcp_data[0:12])
        flags = tcp_data[13]
        
        return {
            'dst_mac': dst_mac,
            'src_mac': src_mac,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'seq': seq,
            'ack': ack,
            'flags': flags,
            'syn': bool(flags & 0x02),
            'ack_flag': bool(flags & 0x10),
            'raw_frame': data
        }
        
    except Exception as e:
        logger.error(f"Frame parsing error: {e}")
        return None

def create_syn_ack_frame(original_frame_info):
    """Create SYN-ACK ethernet frame response"""
    try:
        # Ethernet header (swap MACs)
        eth_header = bytes.fromhex(original_frame_info['src_mac'].replace(':', ''))  # dst (original src)
        eth_header += bytes.fromhex(original_frame_info['dst_mac'].replace(':', ''))  # src (original dst) 
        eth_header += struct.pack('>H', 0x0800)  # IPv4
        
        # IP header (swap IPs)
        src_ip_bytes = socket.inet_aton(original_frame_info['dst_ip'])
        dst_ip_bytes = socket.inet_aton(original_frame_info['src_ip'])
        
        ip_header = struct.pack('>BBHHHBBH4s4s',
            0x45,  # Version + IHL
            0,     # ToS
            40,    # Total length (20 IP + 20 TCP)
            0x1234, # ID
            0,     # Flags + Fragment offset
            64,    # TTL
            6,     # Protocol (TCP)
            0,     # Checksum (kernel will fill)
            src_ip_bytes,
            dst_ip_bytes
        )
        
        # TCP header (swap ports)
        tcp_header = struct.pack('>HHLLBBHHH',
            original_frame_info['dst_port'],     # Source port (our port)
            original_frame_info['src_port'],     # Dest port (client port)
            2000,                                # Our sequence number
            original_frame_info['seq'] + 1,      # ACK number
            0x50,                                # Header length (5 words)
            0x12,                                # Flags: SYN + ACK
            65535,                               # Window size
            0,                                   # Checksum (will calculate)
            0                                    # Urgent pointer
        )
        
        return eth_header + ip_header + tcp_header
        
    except Exception as e:
        logger.error(f"Error creating SYN-ACK frame: {e}")
        return None

def main():
    """Packet socket TCP interceptor"""
    try:
        # Create packet socket to capture all traffic on bridge interface
        # ETH_P_ALL = 0x0003 captures all ethernet frames
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        
        # Bind to bridge interface
        sock.bind(('br0', 0))
        
        logger.info("🔍 Packet socket interceptor started on br0")
        logger.info("Listening for TCP packets at ethernet level...")
        
        while True:
            data, addr = sock.recvfrom(65535)
            
            # Parse the ethernet frame
            frame_info = parse_ethernet_frame(data)
            
            if frame_info and frame_info['dst_port'] in [8080, 9999]:
                logger.info(f"🎯 PACKET SOCKET intercepted TCP frame:")
                logger.info(f"   Ethernet: {frame_info['src_mac']} -> {frame_info['dst_mac']}")
                logger.info(f"   IP: {frame_info['src_ip']}:{frame_info['src_port']} -> {frame_info['dst_ip']}:{frame_info['dst_port']}")
                logger.info(f"   Flags: 0x{frame_info['flags']:02x} ({'SYN' if frame_info['syn'] else ''} {'ACK' if frame_info['ack_flag'] else ''})")
                
                if frame_info['syn'] and not frame_info['ack_flag']:
                    logger.info("📥 TCP SYN detected at PACKET SOCKET level!")
                    
                    # Create and send SYN-ACK response
                    syn_ack_frame = create_syn_ack_frame(frame_info)
                    if syn_ack_frame:
                        try:
                            # Send response frame back through the same socket
                            sock.send(syn_ack_frame)
                            logger.info("📤 SYN-ACK frame sent back through packet socket!")
                        except Exception as e:
                            logger.error(f"Error sending SYN-ACK frame: {e}")
                
    except PermissionError:
        logger.error("❌ Permission denied - run as root: sudo python3 packet_socket_interceptor.py")
    except Exception as e:
        logger.error(f"Packet socket error: {e}")
        logger.info("Make sure the br0 interface exists and you're running as root")

if __name__ == "__main__":
    main()
