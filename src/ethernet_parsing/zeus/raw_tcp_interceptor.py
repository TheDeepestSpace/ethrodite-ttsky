#!/usr/bin/env python3
"""
Raw socket TCP interceptor - manually handle TCP SYN packets
"""
import socket
import struct
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_tcp_packet(data):
    """Parse TCP packet from raw socket data"""
    try:
        # Parse IP header
        version_ihl = data[0]
        ihl = (version_ihl & 0xf) * 4
        
        # Skip to TCP header  
        tcp_data = data[ihl:]
        
        # Parse TCP header
        src_port, dst_port, seq, ack_num = struct.unpack('!HHLL', tcp_data[:12])
        flags_window = struct.unpack('!HH', tcp_data[12:16])
        flags = (flags_window[0] >> 8) & 0x3f
        
        return {
            'ip_header_len': ihl,
            'src_port': src_port,
            'dst_port': dst_port,
            'seq': seq,
            'ack_num': ack_num,
            'flags': flags,
            'syn': bool(flags & 0x02),
            'ack': bool(flags & 0x10),
            'window': flags_window[1]
        }
    except Exception as e:
        logger.error(f"TCP parsing error: {e}")
        return None

def create_syn_ack_response(src_ip, dst_ip, src_port, dst_port, ack_seq):
    """Create a TCP SYN-ACK response packet"""
    try:
        # IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45,  # Version (4) + IHL (5)
            0,     # ToS
            40,    # Total length (20 IP + 20 TCP)
            0x1234, # ID
            0,     # Flags + Fragment offset
            64,    # TTL
            6,     # Protocol (TCP)
            0,     # Checksum (will be filled by kernel)
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip)
        )
        
        # TCP header
        tcp_header = struct.pack('!HHLLBBHHH',
            src_port,      # Source port
            dst_port,      # Destination port  
            1,             # Sequence number
            ack_seq + 1,   # Acknowledgment number
            0x50,          # Header length (5 words = 20 bytes)
            0x12,          # Flags: SYN + ACK
            65535,         # Window size
            0,             # Checksum (will calculate)
            0              # Urgent pointer
        )
        
        return ip_header + tcp_header
    except Exception as e:
        logger.error(f"Error creating SYN-ACK: {e}")
        return None

def main():
    """Raw socket TCP handler"""
    try:
        # Create raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        
        logger.info("🔍 Raw socket TCP interceptor started")
        logger.info("Listening for TCP packets to ports 8080 and 9999...")
        
        while True:
            data, addr = sock.recvfrom(65535)
            
            tcp_info = parse_tcp_packet(data)
            if tcp_info and tcp_info['dst_port'] in [8080, 9999]:
                logger.info(f"🎯 TCP packet intercepted from {addr[0]}:{tcp_info['src_port']} to port {tcp_info['dst_port']}")
                
                if tcp_info['syn'] and not tcp_info['ack']:
                    logger.info("📥 SYN packet detected - attempting manual response")
                    
                    # Create SYN-ACK response
                    response = create_syn_ack_response(
                        "10.0.0.2",              # Our IP
                        addr[0],                 # Client IP
                        tcp_info['dst_port'],    # Our port
                        tcp_info['src_port'],    # Client port
                        tcp_info['seq']          # Acknowledge their sequence
                    )
                    
                    if response:
                        try:
                            # Send response
                            response_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                            response_sock.sendto(response, (addr[0], 0))
                            response_sock.close()
                            logger.info("📤 SYN-ACK response sent!")
                        except Exception as e:
                            logger.error(f"Error sending SYN-ACK: {e}")
                
    except PermissionError:
        logger.error("❌ Permission denied - run as root: sudo python3 raw_tcp_interceptor.py")
    except Exception as e:
        logger.error(f"Raw socket error: {e}")

if __name__ == "__main__":
    main()
