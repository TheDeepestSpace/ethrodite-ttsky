#!/usr/bin/env python3
"""
Direct TAP-based HTTP server - bypasses the kernel network stack entirely
Reads ethernet frames directly from TAP interface and responds manually
"""
import os
import sys
import fcntl
import struct
import socket
import logging
import select

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
TAP_DEVICE = '/dev/net/tun'
TAP_INTERFACE = 'tap0'
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# Fixed MAC addresses
TAP_MAC = 'aa:bb:cc:dd:ee:fe'
DUT_MAC = '00:11:22:33:44:55'

class DirectTAPHTTPServer:
    """HTTP server that works directly on TAP interface"""
    
    def __init__(self):
        self.tap_fd = None
        
    def open_tap(self):
        """Open existing TAP interface"""
        try:
            self.tap_fd = os.open(TAP_DEVICE, os.O_RDWR)
            
            # Attach to existing TAP interface
            flags = IFF_TAP | IFF_NO_PI
            ifr = struct.pack('16sH', TAP_INTERFACE.encode('utf-8'), flags)
            fcntl.ioctl(self.tap_fd, 0x400454ca, ifr)  # TUNSETIFF
            
            logger.info(f"✅ Opened TAP interface {TAP_INTERFACE}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to open TAP interface: {e}")
            return False
    
    def parse_ethernet_frame(self, data):
        """Parse ethernet frame for TCP packets"""
        try:
            if len(data) < 14:
                return None
                
            # Parse ethernet header
            dst_mac = data[0:6].hex(':')
            src_mac = data[6:12].hex(':')
            ethertype = struct.unpack('>H', data[12:14])[0]
            
            if ethertype != 0x0800:  # Not IPv4
                return None
                
            # Parse IP header
            if len(data) < 34:  # Minimum for IP + TCP headers
                return None
                
            ip_data = data[14:]
            protocol = ip_data[9]
            
            if protocol != 6:  # Not TCP
                return None
                
            src_ip = '.'.join(str(b) for b in ip_data[12:16])
            dst_ip = '.'.join(str(b) for b in ip_data[16:20])
            
            # Parse TCP header
            tcp_data = data[34:]  # Assuming 20-byte IP header
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
                'fin': bool(flags & 0x01),
                'tcp_data': tcp_data,
                'payload': tcp_data[20:] if len(tcp_data) > 20 else b''  # TCP payload
            }
            
        except Exception as e:
            logger.error(f"Frame parsing error: {e}")
            return None
    
    def create_tcp_response(self, request_info, response_data, flags="PA"):
        """Create TCP response frame"""
        try:
            # Ethernet header (swap MACs)
            eth_header = bytes.fromhex(request_info['src_mac'].replace(':', ''))  # dst
            eth_header += bytes.fromhex(TAP_MAC.replace(':', ''))  # src (our TAP MAC)
            eth_header += struct.pack('>H', 0x0800)  # IPv4
            
            # IP header
            ip_total_length = 20 + 20 + len(response_data)  # IP + TCP + data
            ip_header = struct.pack('>BBHHHBBH4s4s',
                0x45,  # Version + IHL
                0,     # ToS
                ip_total_length,  # Total length
                0x1234, # ID
                0,     # Flags + Fragment offset
                64,    # TTL
                6,     # Protocol (TCP)
                0,     # Checksum (kernel fills)
                socket.inet_aton(request_info['dst_ip']),  # Our IP
                socket.inet_aton(request_info['src_ip'])   # Client IP
            )
            
            # TCP header
            flag_value = 0x18 if flags == "PA" else 0x12 if flags == "SA" else 0x10  # PSH+ACK, SYN+ACK, or ACK
            tcp_header = struct.pack('>HHLLBBHHH',
                request_info['dst_port'],        # Our port
                request_info['src_port'],        # Client port
                1000,                            # Our sequence number
                request_info['seq'] + len(request_info['payload']) + (1 if request_info['syn'] else 0),  # ACK number
                0x50,                            # Header length (5 words = 20 bytes)
                flag_value,                      # Flags
                65535,                           # Window size
                0,                               # Checksum (will calculate later)
                0                                # Urgent pointer
            )
            
            return eth_header + ip_header + tcp_header + response_data
            
        except Exception as e:
            logger.error(f"Error creating TCP response: {e}")
            return None
    
    def handle_http_request(self, request_info):
        """Handle HTTP request and return response"""
        payload = request_info['payload']
        
        # Check if it's an HTTP request
        if payload.startswith(b'GET') or payload.startswith(b'POST'):
            logger.info(f"📥 HTTP request: {payload[:50]}...")
            
            # Create simple HTTP response
            http_response = b"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
Content-Length: 71\r
Connection: close\r
\r
<html><body><h1>SUCCESS!</h1><p>TAP HTTP Server Working!</p></body></html>"""
            
            return self.create_tcp_response(request_info, http_response, "PA")
        
        return None
    
    def send_syn_ack(self, request_info):
        """Send SYN-ACK response"""
        syn_ack_frame = self.create_tcp_response(request_info, b"", "SA")
        if syn_ack_frame:
            os.write(self.tap_fd, syn_ack_frame)
            logger.info("📤 SYN-ACK sent!")
            return True
        return False
    
    def run(self):
        """Main server loop"""
        if not self.open_tap():
            return
            
        logger.info("🚀 Direct TAP HTTP server started!")
        logger.info("Listening for HTTP requests on TAP interface...")
        
        try:
            while True:
                # Use select for non-blocking read
                ready, _, _ = select.select([self.tap_fd], [], [], 1.0)
                
                if ready:
                    # Read frame from TAP
                    data = os.read(self.tap_fd, 1500)
                    
                    # Parse the frame
                    frame_info = self.parse_ethernet_frame(data)
                    
                    if frame_info and frame_info['dst_port'] == 8080:
                        logger.info(f"🎯 TAP HTTP server got TCP packet:")
                        logger.info(f"   {frame_info['src_ip']}:{frame_info['src_port']} -> {frame_info['dst_ip']}:{frame_info['dst_port']}")
                        logger.info(f"   Flags: 0x{frame_info['flags']:02x} ({'SYN' if frame_info['syn'] else ''} {'ACK' if frame_info['ack_flag'] else ''})")
                        
                        if frame_info['syn'] and not frame_info['ack_flag']:
                            # TCP SYN - respond with SYN-ACK
                            logger.info("📥 TCP SYN - sending SYN-ACK")
                            self.send_syn_ack(frame_info)
                            
                        elif frame_info['payload']:
                            # Data packet - check for HTTP request
                            logger.info(f"📨 TCP data packet: {len(frame_info['payload'])} bytes")
                            response = self.handle_http_request(frame_info)
                            if response:
                                os.write(self.tap_fd, response)
                                logger.info("📤 HTTP response sent!")
        
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.tap_fd:
                os.close(self.tap_fd)
                logger.info("TAP interface closed")

def main():
    if os.geteuid() != 0:
        logger.error("❌ Must run as root to access TAP interface")
        sys.exit(1)
        
    server = DirectTAPHTTPServer()
    server.run()

if __name__ == "__main__":
    main()
