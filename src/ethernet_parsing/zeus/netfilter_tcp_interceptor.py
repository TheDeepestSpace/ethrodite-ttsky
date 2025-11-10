#!/usr/bin/env python3
"""
NFQUEUE-based TCP interceptor - intercepts packets at netfilter level
This runs closer to kernel space than regular sockets
"""
try:
    from netfilterqueue import NetfilterQueue
    import scapy.all as scapy
    NETFILTER_AVAILABLE = True
except ImportError:
    NETFILTER_AVAILABLE = False

import logging
import subprocess
import signal
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetfilterTCPInterceptor:
    def __init__(self):
        self.nfqueue = None
        self.iptables_rules_added = False
        
    def setup_iptables_rules(self):
        """Add iptables rules to redirect TCP packets to NFQUEUE"""
        try:
            # Add rule to send TCP packets destined for ports 8080,9999 to NFQUEUE
            subprocess.run([
                'iptables', '-I', 'INPUT', '-p', 'tcp', 
                '--dport', '8080', '-j', 'NFQUEUE', '--queue-num', '0'
            ], check=True)
            
            subprocess.run([
                'iptables', '-I', 'INPUT', '-p', 'tcp',
                '--dport', '9999', '-j', 'NFQUEUE', '--queue-num', '0' 
            ], check=True)
            
            logger.info("✅ Iptables rules added for NFQUEUE interception")
            self.iptables_rules_added = True
            
        except Exception as e:
            logger.error(f"Failed to add iptables rules: {e}")
            return False
        return True
    
    def cleanup_iptables_rules(self):
        """Remove iptables rules"""
        if self.iptables_rules_added:
            try:
                subprocess.run([
                    'iptables', '-D', 'INPUT', '-p', 'tcp',
                    '--dport', '8080', '-j', 'NFQUEUE', '--queue-num', '0'
                ], check=False)
                
                subprocess.run([
                    'iptables', '-D', 'INPUT', '-p', 'tcp',
                    '--dport', '9999', '-j', 'NFQUEUE', '--queue-num', '0'
                ], check=False)
                
                logger.info("🧹 Iptables rules removed")
            except Exception as e:
                logger.warning(f"Error removing iptables rules: {e}")
    
    def handle_packet(self, packet):
        """Handle intercepted packet"""
        try:
            # Parse with Scapy
            pkt = scapy.IP(packet.get_payload())
            
            if pkt.proto == 6 and hasattr(pkt, 'payload'):  # TCP
                tcp = pkt.payload
                
                logger.info(f"🎯 NETFILTER intercepted TCP: {pkt.src}:{tcp.sport} -> {pkt.dst}:{tcp.dport}")
                
                # Check if it's a SYN packet
                if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN but not ACK
                    logger.info("📥 TCP SYN packet intercepted at NETFILTER level!")
                    logger.info(f"   Seq: {tcp.seq}, Flags: {tcp.flags:02x}")
                    
                    # Create and send SYN-ACK response
                    self.send_syn_ack_response(pkt, tcp)
                    
                    # Accept the packet (let it continue to userspace too)
                    packet.accept()
                    return
                
            # Accept all other packets
            packet.accept()
            
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
            packet.accept()
    
    def send_syn_ack_response(self, ip_pkt, tcp_pkt):
        """Send SYN-ACK response using Scapy"""
        try:
            # Create SYN-ACK response
            response = scapy.IP(
                src=ip_pkt.dst,
                dst=ip_pkt.src
            ) / scapy.TCP(
                sport=tcp_pkt.dport,
                dport=tcp_pkt.sport,
                seq=1000,
                ack=tcp_pkt.seq + 1,
                flags="SA"  # SYN-ACK
            )
            
            # Send the response
            scapy.send(response, verbose=False)
            logger.info("📤 SYN-ACK response sent via Scapy!")
            
        except Exception as e:
            logger.error(f"Error sending SYN-ACK: {e}")
    
    def start(self):
        """Start the netfilter interceptor"""
        if not NETFILTER_AVAILABLE:
            logger.error("NetfilterQueue not available. Install with: pip install NetfilterQueue scapy")
            return False
            
        if not self.setup_iptables_rules():
            return False
            
        try:
            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(0, self.handle_packet)
            
            logger.info("🔍 NFQUEUE TCP interceptor started")
            logger.info("This intercepts packets at the netfilter level (closer to kernel)")
            
            self.nfqueue.run()
            
        except KeyboardInterrupt:
            logger.info("Interceptor stopped by user")
        except Exception as e:
            logger.error(f"NFQUEUE error: {e}")
        finally:
            self.cleanup_iptables_rules()
            
        return True

def signal_handler(signum, frame):
    """Handle cleanup on exit"""
    logger.info("Cleaning up...")
    # The cleanup will happen in the finally block
    os._exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    interceptor = NetfilterTCPInterceptor()
    interceptor.start()

if __name__ == "__main__":
    main()
