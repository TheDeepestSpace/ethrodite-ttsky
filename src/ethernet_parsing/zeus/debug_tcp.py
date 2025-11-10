#!/usr/bin/env python3
"""
Debug TCP connectivity by listening for packets with raw sockets
"""
import socket
import struct
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_tcp_packet(data):
    """Parse TCP packet from raw socket data"""
    try:
        # Skip IP header to get to TCP
        ip_header_len = (data[0] & 0xf) * 4
        tcp_data = data[ip_header_len:]
        
        # Parse TCP header
        src_port, dst_port, seq, ack, flags = struct.unpack('!HHLLH', tcp_data[:14])
        flags = flags & 0x3f  # Last 6 bits are TCP flags
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'seq': seq,
            'flags': flags,
            'syn': bool(flags & 0x02),
            'ack': bool(flags & 0x10),
            'fin': bool(flags & 0x01),
            'rst': bool(flags & 0x04)
        }
    except Exception as e:
        logger.error(f"TCP parsing error: {e}")
        return None

def main():
    """Monitor TCP traffic with raw socket"""
    try:
        # Create raw socket for TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.bind(('10.0.0.2', 0))  # Bind to our bridge IP
        
        logger.info("Raw TCP socket listening on 10.0.0.2 for port 8080 traffic...")
        
        while True:
            data, addr = sock.recvfrom(65535)
            logger.info(f"Raw TCP packet from {addr}: {len(data)} bytes")
            
            tcp_info = parse_tcp_packet(data)
            if tcp_info and tcp_info['dst_port'] == 8080:
                flag_str = []
                if tcp_info['syn']: flag_str.append('SYN')
                if tcp_info['ack']: flag_str.append('ACK')
                if tcp_info['fin']: flag_str.append('FIN')
                if tcp_info['rst']: flag_str.append('RST')
                
                logger.info(f"🎯 TCP to port 8080: {tcp_info['src_port']} -> {tcp_info['dst_port']}")
                logger.info(f"   Flags: {','.join(flag_str)}, Seq: {tcp_info['seq']}")
                
                # Try to respond with SYN-ACK if it's a SYN
                if tcp_info['syn'] and not tcp_info['ack']:
                    logger.info("🔄 Attempting to send SYN-ACK response...")
                    # We would need to craft a proper TCP response here
                    
    except Exception as e:
        logger.error(f"Raw socket error: {e}")
        logger.info("Try running with: sudo python3 debug_tcp.py")

if __name__ == "__main__":
    main()
