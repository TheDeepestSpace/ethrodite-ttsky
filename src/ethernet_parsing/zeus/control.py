"""
Control script for UART-over-TCP and TAP interface HTTP server.
Runs both services concurrently and handles graceful shutdown on Ctrl+C.
"""

import asyncio
import signal
import socket
import struct
import fcntl
import os
import sys
import subprocess
import select
from http.server import HTTPServer, BaseHTTPRequestHandler
try:
    from scapy.all import ARP, Ether, sendp, sniff, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not available, ARP responder disabled")
import threading
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
UART_TCP_PORT = 7000
HTTP_HOST = '0.0.0.0'  # Bind to all interfaces - let kernel handle routing
HTTP_PORT = 8080
TAP_DEVICE = '/dev/net/tun'
TAP_INTERFACE = 'tap0'
BRIDGE_NAME = 'br0'

# Fixed MAC addresses for consistent testing
BRIDGE_MAC = 'aa:bb:cc:dd:ee:ff'  # Fixed MAC for bridge
TAP_MAC = 'aa:bb:cc:dd:ee:fe'     # Fixed MAC for TAP (similar but different)
DUT_MAC = '00:11:22:33:44:55'     # DUT MAC address (used in test scripts)

# Global flags for shutdown
shutdown_event = threading.Event()

class TAPInterface:
  """Handle TAP interface operations with bridge setup"""

  def __init__(self, interface_name='tap0'):
    self.interface_name = interface_name
    self.tap_fd = None

  def create_tap(self):
    """Create TAP interface and set up bridge"""
    try:
      # Set up bridge and TAP interface (this now creates the TAP interface via ip command)
      self._setup_bridge()

      # Now open the TAP device file descriptor for reading/writing frames
      self.tap_fd = os.open(TAP_DEVICE, os.O_RDWR)

      # Attach to the existing TAP interface with NO_PI flag to avoid headers
      IFF_TAP = 0x0002
      IFF_NO_PI = 0x1000  # No packet information header
      flags = IFF_TAP | IFF_NO_PI
      ifr = struct.pack('16sH', self.interface_name.encode('utf-8'), flags)
      fcntl.ioctl(self.tap_fd, 0x400454ca, ifr)  # TUNSETIFF

      logger.info(f"TAP interface {self.interface_name} file descriptor opened successfully")

      return True
    except Exception as e:
        logger.error(f"Failed to create TAP interface: {e}")
        return False

  def _setup_bridge(self):
    """Set up network bridge to connect TAP interface to local HTTP server"""
    try:
      logger.info("Setting up TAP interface with local networking for DUT testing...")

      # Clean up any existing interfaces first
      subprocess.run(['ip', 'link', 'delete', BRIDGE_NAME],
                     check=False, capture_output=True)
      subprocess.run(['ip', 'link', 'delete', self.interface_name],
                     check=False, capture_output=True)

      # Create TAP interface using ip command (more reliable than just the file descriptor)
      subprocess.run(['ip', 'tuntap', 'add', self.interface_name, 'mode', 'tap'],
                     check=True, capture_output=True)
      logger.info(f"TAP interface {self.interface_name} created via ip command")

      # Set fixed MAC address for TAP interface
      subprocess.run(['ip', 'link', 'set', self.interface_name, 'address', TAP_MAC],
                     check=True, capture_output=True)
      logger.info(f"TAP interface {self.interface_name} MAC set to {TAP_MAC}")

      # Create bridge interface
      subprocess.run(['ip', 'link', 'add', 'name', BRIDGE_NAME, 'type', 'bridge'],
                     check=True, capture_output=True)
      logger.info(f"Bridge {BRIDGE_NAME} created")

      # Set fixed MAC address for bridge interface
      subprocess.run(['ip', 'link', 'set', BRIDGE_NAME, 'address', BRIDGE_MAC],
                     check=True, capture_output=True)
      logger.info(f"Bridge {BRIDGE_NAME} MAC set to {BRIDGE_MAC}")

      # Bring up TAP interface
      subprocess.run(['ip', 'link', 'set', self.interface_name, 'up'],
                     check=True, capture_output=True)

      # Add TAP interface to bridge
      subprocess.run(['ip', 'link', 'set', self.interface_name, 'master', BRIDGE_NAME],
                     check=True, capture_output=True)
      logger.info(f"TAP interface {self.interface_name} added to bridge {BRIDGE_NAME}")

      # Configure TAP interface directly with an IP instead of bridge
      subprocess.run(['ip', 'addr', 'add', '10.0.0.2/24', 'dev', self.interface_name],
                     check=True, capture_output=True)
      
      # Configure bridge with gateway IP  
      subprocess.run(['ip', 'addr', 'add', '10.0.0.1/24', 'dev', BRIDGE_NAME],
                     check=True, capture_output=True)

      # Bring up bridge interface
      subprocess.run(['ip', 'link', 'set', BRIDGE_NAME, 'up'],
                     check=True, capture_output=True)

      # Enable IP forwarding for better local networking
      try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
          f.write('1')
        logger.info("IP forwarding enabled")
      except Exception as e:
        logger.warning(f"Could not enable IP forwarding: {e}")

      # Enable accepting packets on bridge interface
      try:
        subprocess.run(['sysctl', '-w', 'net.bridge.bridge-nf-call-iptables=0'],
                       check=False, capture_output=True)
        subprocess.run(['sysctl', '-w', 'net.bridge.bridge-nf-call-ip6tables=0'],
                       check=False, capture_output=True)
        logger.info("Bridge netfilter disabled for better TAP performance")
      except Exception as e:
        logger.warning(f"Could not disable bridge netfilter: {e}")

      # Ensure firewall allows traffic to our HTTP server and enable local delivery
      try:
        # Allow connections to port 8080 from bridge and TAP interfaces
        subprocess.run(['iptables', '-I', 'INPUT', '-i', BRIDGE_NAME, '-p', 'tcp', '--dport', str(HTTP_PORT), '-j', 'ACCEPT'],
                       check=False, capture_output=True)
        subprocess.run(['iptables', '-I', 'INPUT', '-i', TAP_INTERFACE, '-p', 'tcp', '--dport', str(HTTP_PORT), '-j', 'ACCEPT'],
                       check=False, capture_output=True)
        subprocess.run(['iptables', '-I', 'INPUT', '-s', '10.0.0.0/24', '-p', 'tcp', '--dport', str(HTTP_PORT), '-j', 'ACCEPT'],
                       check=False, capture_output=True)
        
        # Enable local delivery for packets destined to 10.0.0.2 
        subprocess.run(['sysctl', '-w', 'net.ipv4.conf.all.accept_local=1'], check=False, capture_output=True)
        subprocess.run(['sysctl', '-w', f'net.ipv4.conf.{BRIDGE_NAME}.accept_local=1'], check=False, capture_output=True)
        
        logger.info(f"Firewall rules and local delivery enabled for TCP:{HTTP_PORT}")
      except Exception as e:
        logger.warning(f"Could not configure firewall/routing: {e}")

      # Add explicit route for our local test network
      subprocess.run(['ip', 'route', 'add', '10.0.0.0/24', 'dev', BRIDGE_NAME],
                     check=False, capture_output=True)  # Ignore if exists

      # Remove any conflicting routes from TAP interface
      subprocess.run(['ip', 'route', 'del', '10.0.0.0/24', 'dev', self.interface_name],
                     check=False, capture_output=True)

      logger.info(f"Bridge {BRIDGE_NAME} configured with IPs 10.0.0.1 and 10.0.0.2")
      logger.info(f"Fixed MAC addresses: Bridge={BRIDGE_MAC}, TAP={TAP_MAC}, DUT={DUT_MAC}")
      logger.info("TAP interface ready for local DUT HTTP testing")

    except subprocess.CalledProcessError as e:
      logger.error(f"Failed to set up bridge: {e}")
      logger.error(f"Command output: {e.stderr if hasattr(e, 'stderr') else 'No stderr'}")
      # Try to continue anyway
    except Exception as e:
      logger.error(f"Bridge setup error: {e}")

  def read_frame(self):
    """Read ethernet frame from TAP interface (non-blocking)"""
    if self.tap_fd:
      try:
        # Make it non-blocking
        import fcntl
        flags = fcntl.fcntl(self.tap_fd, fcntl.F_GETFL)
        fcntl.fcntl(self.tap_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        return os.read(self.tap_fd, 1500)  # MTU size
      except BlockingIOError:
        # No data available
        return None
      except Exception as e:
        logger.error(f"Error reading from TAP: {e}")
        return None
    return None

  def write_frame(self, frame):
    """Write ethernet frame to TAP interface"""
    if self.tap_fd:
      try:
        os.write(self.tap_fd, frame)
        return True
      except Exception as e:
        logger.error(f"Error writing to TAP: {e}")
        return False
    return False

  def close(self):
      """Close TAP interface and cleanup bridge"""
      if self.tap_fd:
        os.close(self.tap_fd)
        logger.info("TAP interface file descriptor closed")

      # Cleanup bridge and TAP interface
      try:
        # Remove TAP from bridge first
        subprocess.run(['ip', 'link', 'set', self.interface_name, 'nomaster'],
                       check=False, capture_output=True)
        # Delete bridge
        subprocess.run(['ip', 'link', 'delete', BRIDGE_NAME],
                       check=False, capture_output=True)
        # Delete TAP interface
        subprocess.run(['ip', 'link', 'delete', self.interface_name],
                       check=False, capture_output=True)
        logger.info("TAP interface and bridge cleaned up")
      except Exception as e:
        logger.debug(f"Cleanup error (ignored): {e}")

class SimpleHTTPHandler(BaseHTTPRequestHandler):
  """Simple HTTP request handler with detailed logging"""

  def setup(self):
    """Called before handle() - log connection attempts"""
    super().setup()
    logger.info(f"🔗 HTTP TCP connection established from {self.client_address}")
    logger.info(f"🔗 Socket info: {self.connection.getsockname()} <- {self.connection.getpeername()}")

  def parse_request(self):
    """Override to log raw request parsing"""
    logger.info(f"📥 HTTP parsing request from {self.client_address}")
    result = super().parse_request()
    if result:
      logger.info(f"📥 HTTP parsed: {self.command} {self.path} {self.request_version}")
    else:
      logger.warning(f"❌ HTTP failed to parse request from {self.client_address}")
    return result

  def do_GET(self):
    """Handle GET requests"""
    logger.info(f"🌐 Processing HTTP GET request: {self.path} from {self.client_address}")
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.send_header('Connection', 'close')
    self.end_headers()

    response = f"""
    <html>
    <head><title>TAP HTTP Server</title></head>
    <body>
    <h1>Hello from Bridged TAP Interface!</h1>
    <p>Request path: {self.path}</p>
    <p>Client: {self.client_address}</p>
    <p>Server running on {HTTP_HOST}:{HTTP_PORT}</p>
    <p>Your DUT's ethernet frames are working! 🎉</p>
    </body>
    </html>
    """
    self.wfile.write(response.encode('utf-8'))
    logger.info(f"✅ HTTP response sent to {self.client_address}")

  def finish(self):
    """Called after handle() - log connection cleanup"""
    logger.info(f"🔚 HTTP connection finished to {self.client_address}")
    super().finish()

  def handle_one_request(self):
    """Override to catch connection errors"""
    try:
      logger.info(f"📨 HTTP handling one request from {self.client_address}")
      super().handle_one_request()
    except Exception as e:
      logger.error(f"❌ HTTP request handling error from {self.client_address}: {e}")

  def log_message(self, format, *args):
    """Override default logging"""
    logger.info(f"📋 HTTP: {format % args}")

  def handle_one_request(self):
    """Handle a single HTTP request - with connection logging"""
    try:
      logger.info(f"🌐 Processing HTTP request from {self.client_address}")
      super().handle_one_request()
    except Exception as e:
      logger.error(f"🌐 HTTP request error from {self.client_address}: {e}")

  def log_message(self, format, *args):
    """Override to use our logger"""
    logger.info(f"HTTP: {format % args}")

class UARTTCPServer:
  """UART over TCP server"""

  def __init__(self, port=7000, tap_interface=None):
    self.port = port
    self.tap_interface = tap_interface
    self.server_socket = None
    self.client_socket = None
    self.running = False

  async def start_server(self):
    """Start the UART TCP server"""
    try:
      self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      self.server_socket.bind(('localhost', self.port))
      self.server_socket.listen(1)
      self.server_socket.settimeout(1.0)  # Non-blocking with timeout

      logger.info(f"UART-over-TCP server listening on localhost:{self.port}")
      self.running = True

      while self.running and not shutdown_event.is_set():
        try:
          self.client_socket, addr = self.server_socket.accept()
          logger.info(f"UART client connected from {addr}")

          # Handle client connection
          await self.handle_client()

        except socket.timeout:
          continue
        except Exception as e:
          if self.running:
            logger.error(f"UART server error: {e}")

    except Exception as e:
      logger.error(f"Failed to start UART server: {e}")

  async def handle_client(self):
    """Handle UART client connection"""
    try:
      self.client_socket.settimeout(0.1)

      while self.running and not shutdown_event.is_set():
        try:
          # Check for incoming data from UART (DUT)
          data = self.client_socket.recv(1024)
          if not data:
              break

          # Log received data with detailed analysis
          logger.info(f"UART received ethernet frame: {data.hex()} ({len(data)} bytes)")
          self._analyze_ethernet_frame(data, "INCOMING")

          # Forward ethernet frame to TAP interface
          if self.tap_interface:
            if self.tap_interface.write_frame(data):
              logger.info("✅ Ethernet frame written to TAP interface (bridged to kernel)")
              # Add a small delay to let the kernel process it
              await asyncio.sleep(0.001)

              # Give more time for the network stack to process and respond
              response_found = False
              for attempt in range(20):  # Try more times since bridge adds latency
                await asyncio.sleep(0.01 * (attempt + 1))  # 0.01, 0.02, 0.03... seconds

                response_frame = self.tap_interface.read_frame()
                if response_frame:
                  logger.info(f"TAP raw frame (attempt {attempt+1}): {response_frame.hex()} ({len(response_frame)} bytes)")
                  frame_info = self._is_relevant_ipv4_frame(response_frame)
                  if frame_info:
                    logger.info("✅ Frame passed relevance filter")
                    # Remove TAP header if present (frame_info contains offset)
                    offset = frame_info.get('offset', 0)
                    clean_frame = response_frame[offset:] if offset > 0 else response_frame
                    logger.info(f"Sending clean ethernet frame ({len(clean_frame)} bytes, removed {offset}-byte TAP header)")
                    # Send response frame back to DUT via UART
                    self.client_socket.send(clean_frame)
                    logger.info("Response frame sent back to DUT via UART")
                    response_found = True
                    break
                  else:
                    logger.info("❌ Frame filtered out by relevance check")

              if not response_found:
                # Send simple ACK if no response frame after all attempts
                ack = b'\x06'  # ACK byte
                self.client_socket.send(ack)
            else:
              logger.error("Failed to write ethernet frame to TAP interface")
              # Send NACK
              nack = b'\x15'  # NACK byte
              self.client_socket.send(nack)

        except socket.timeout:
          # Still check for TAP responses even if no UART data
          if self.tap_interface:
            response_frame = self.tap_interface.read_frame()
            if response_frame:
              logger.info(f"TAP unsolicited raw frame: {response_frame.hex()} ({len(response_frame)} bytes)")
              frame_info = self._is_relevant_ipv4_frame(response_frame)
              if frame_info:
                logger.info("✅ Unsolicited frame passed relevance filter")
                offset = frame_info.get('offset', 0)
                clean_frame = response_frame[offset:] if offset > 0 else response_frame
                self.client_socket.send(clean_frame)
              else:
                logger.info("❌ Unsolicited frame filtered out")
          continue
        except Exception as e:
          logger.error(f"UART client error: {e}")
          break

    finally:
      if self.client_socket:
        self.client_socket.close()
        self.client_socket = None
        logger.info("UART client disconnected")

  def _is_relevant_ipv4_frame(self, frame):
    """Check if frame is a relevant IPv4 response (not housekeeping traffic)"""
    if len(frame) < 14:  # Minimum ethernet header
      return False

    logger.info(f"Raw frame analysis: length={len(frame)}, first 20 bytes: {frame[:20].hex()}")

    # With IFF_NO_PI flag, we should now get clean ethernet frames without headers
    # But let's still check multiple offsets to be safe
    for offset in [0, 4]:  # Try with and without any potential header
      if len(frame) < offset + 14:  # Not enough data
        continue

      # Extract ethertype from ethernet header at this offset
      ethertype_pos = offset + 12
      if len(frame) >= ethertype_pos + 2:
        ethertype = struct.unpack('>H', frame[ethertype_pos:ethertype_pos+2])[0]

        logger.info(f"Offset {offset}: ethertype=0x{ethertype:04x}")

        if ethertype == 0x0800:  # IPv4 found!
          logger.info(f"✅ IPv4 frame detected at offset {offset}!")

          # Parse ethernet header
          dst_mac = frame[offset:offset+6].hex(':')
          src_mac = frame[offset+6:offset+12].hex(':')
          logger.info(f"Ethernet: {src_mac} -> {dst_mac}")

          # Check IP protocol
          ip_protocol_pos = offset + 23
          if len(frame) >= ip_protocol_pos + 1:
            protocol = frame[ip_protocol_pos]
            logger.info(f"IP protocol: {protocol}")

            # Parse IP addresses
            if len(frame) >= offset + 34:
              src_ip = '.'.join(str(b) for b in frame[offset+26:offset+30])
              dst_ip = '.'.join(str(b) for b in frame[offset+30:offset+34])

              if protocol == 1:  # ICMP
                logger.info(f"🎯 ICMP: {src_ip} -> {dst_ip} - this IS our ping reply!")
                return {'relevant': True, 'offset': offset, 'type': 'ICMP'}
              elif protocol == 6:  # TCP
                logger.info(f"🎯 TCP: {src_ip} -> {dst_ip}")
                return {'relevant': True, 'offset': offset, 'type': 'TCP'}
              elif protocol == 2:  # IGMP
                logger.info(f"IGMP: {src_ip} -> {dst_ip} (housekeeping traffic, filtering out)")
                continue  # Skip IGMP
              else:
                logger.info(f"Other IPv4: {src_ip} -> {dst_ip} (protocol {protocol})")
                # Only accept if it's directed to our DUT's IP ranges
                if (dst_ip.startswith('192.168.1.') or
                    dst_ip.startswith('10.0.0.')):
                  return {'relevant': True, 'offset': offset, 'type': 'Other'}
                else:
                  logger.info("Not directed to our DUT - filtering out")
                  continue

          # If we couldn't parse IPs but it's IPv4, might still be relevant
          return {'relevant': True, 'offset': offset, 'type': 'IPv4'}

        elif ethertype == 0x86dd:  # IPv6
          logger.info(f"IPv6 frame at offset {offset} (filtering out)")
          continue  # Try next offset

    logger.info("❌ No valid IPv4 frame found at any offset")
    return False

  def _analyze_ethernet_frame(self, frame, direction):
    """Analyze and log ethernet frame details"""
    if len(frame) < 14:
      logger.warning(f"{direction} frame too short: {len(frame)} bytes")
      return

    try:
      # Parse ethernet header
      dst_mac = ':'.join(f'{b:02x}' for b in frame[0:6])
      src_mac = ':'.join(f'{b:02x}' for b in frame[6:12])
      ethertype = struct.unpack('>H', frame[12:14])[0]

      logger.info(f"{direction} Ethernet: {src_mac} -> {dst_mac}, Type: 0x{ethertype:04x}")

      if ethertype == 0x0800 and len(frame) >= 34:  # IPv4
        src_ip = '.'.join(str(b) for b in frame[26:30])
        dst_ip = '.'.join(str(b) for b in frame[30:34])
        protocol = frame[23]
        logger.info(f"  IPv4: {src_ip} -> {dst_ip}, Protocol: {protocol}")

        if protocol == 1:  # ICMP
          logger.info(f"  🏓 ICMP packet detected")
        elif protocol == 6:  # TCP
          if len(frame) >= 54:
            src_port = struct.unpack('>H', frame[34:36])[0]
            dst_port = struct.unpack('>H', frame[36:38])[0]
            logger.info(f"  🌐 TCP: {src_port} -> {dst_port}")
      elif ethertype == 0x0806:  # ARP
        logger.info(f"  🔍 ARP packet")
      else:
        logger.info(f"  ❓ Unknown ethertype: 0x{ethertype:04x}")

    except Exception as e:
      logger.error(f"Frame analysis error: {e}")

  def stop(self):
    """Stop the UART server"""
    self.running = False
    if self.client_socket:
      self.client_socket.close()
    if self.server_socket:
      self.server_socket.close()
    logger.info("UART server stopped")

class LoggingHTTPServer(HTTPServer):
  """HTTP Server with detailed connection logging"""

  def server_bind(self):
    """Override to log server binding"""
    super().server_bind()
    logger.info(f"🌐 HTTP server bound to {self.server_address}")

  def handle_request(self):
    """Override to log each request handling"""
    logger.info("🔄 HTTP server handling incoming request...")
    try:
      super().handle_request()
    except Exception as e:
      logger.error(f"❌ HTTP server request handling failed: {e}")

  def process_request(self, request, client_address):
    """Override to log request processing"""
    logger.info(f"⚡ HTTP processing request from {client_address}")
    super().process_request(request, client_address)
    logger.info(f"✅ HTTP request processing completed for {client_address}")

def arp_responder():
  """Respond to ARP requests for our DUT IP (10.0.0.10)"""
  if not SCAPY_AVAILABLE:
    logger.warning("ARP responder disabled - scapy not available")
    return

  DUT_IP = "10.0.0.10"

  def handle_arp(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP request
      if packet[ARP].pdst == DUT_IP:
        logger.info(f"🔍 ARP request for {DUT_IP} from {packet[ARP].psrc} - responding with {DUT_MAC}")
        # Create ARP reply
        arp_reply = ARP(
          op=2,  # ARP reply
          psrc=DUT_IP,
          pdst=packet[ARP].psrc,
          hwsrc=DUT_MAC,
          hwdst=packet[ARP].hwsrc
        )
        eth_reply = Ether(src=DUT_MAC, dst=packet[Ether].src) / arp_reply
        sendp(eth_reply, iface=BRIDGE_NAME, verbose=False)
        logger.info(f"✅ ARP reply sent: {DUT_IP} is at {DUT_MAC}")

  try:
    logger.info(f"🔍 ARP responder starting for {DUT_IP} on {BRIDGE_NAME}")
    sniff(iface=BRIDGE_NAME, prn=handle_arp, filter="arp", store=0)
  except Exception as e:
    logger.error(f"ARP responder error: {e}")

def run_http_server():
  """Run HTTP server in separate thread"""
  try:
    server = LoggingHTTPServer((HTTP_HOST, HTTP_PORT), SimpleHTTPHandler)
    logger.info(f"HTTP server starting on {HTTP_HOST}:{HTTP_PORT}")
    logger.info(f"HTTP server accessible via 10.0.0.2:8080 from bridge network")
    
    # Check if we can bind to the port
    import socket
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
      test_sock.bind(('10.0.0.2', HTTP_PORT))
      logger.info(f"✅ Port {HTTP_PORT} is available on 10.0.0.2")
      test_sock.close()
    except Exception as e:
      logger.warning(f"⚠️  Port {HTTP_PORT} binding test failed: {e}")
      test_sock.close()
    
    server.serve_forever()
  except Exception as e:
    logger.error(f"HTTP server error: {e}")
    return

def run_traffic_monitor():
  """Run traffic monitoring in a separate thread"""
  try:
    logger.info("Starting TAP interface traffic monitoring...")

    # Start tcpdump process - capture ALL traffic (not just IPv4) to see everything
    cmd = [
      'tcpdump',
      '-i', TAP_INTERFACE,
      '-n',           # Don't resolve hosts
      '-l',           # Line buffered output
      '-e',           # Show ethernet headers
      '-t',           # Don't print timestamps
      '-s', '0',      # Capture full packets (not just 96 bytes)
      '-x',           # Show hex dump
      '-v'            # Verbose output
      # Removed 'ip' filter to see ALL traffic including ARP, etc.
    ]

    process = subprocess.Popen(
      cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      universal_newlines=True,
      bufsize=1
    )

    logger.info("Traffic monitor started")

    while not shutdown_event.is_set():
      # Use select to check if data is available (non-blocking)
      ready, _, _ = select.select([process.stdout], [], [], 0.1)

      if ready:
        line = process.stdout.readline()
        if line:
          logger.info(f"TAP traffic: {line.strip()}")
        else:
          # Process ended
          break

      # Check if process is still running
      if process.poll() is not None:
        break

    # Cleanup
    if process.poll() is None:
      process.terminate()
      try:
        process.wait(timeout=2)
      except subprocess.TimeoutExpired:
        process.kill()

  except FileNotFoundError:
    logger.error("tcpdump not found. Please install it with: sudo apt install tcpdump")
  except Exception as e:
    logger.error(f"Traffic monitor error: {e}")
  finally:
    logger.info("Traffic monitor stopped")

def run_bridge_monitor():
  """Monitor bridge traffic separately"""
  try:
    logger.info("Starting bridge traffic monitoring...")

    # Monitor bridge interface
    cmd = [
      'tcpdump',
      '-i', BRIDGE_NAME,
      '-n', '-l', '-e', '-t', '-s', '0', '-x', '-v'
    ]

    process = subprocess.Popen(
      cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      universal_newlines=True,
      bufsize=1
    )

    logger.info("Bridge monitor started")

    while not shutdown_event.is_set():
      ready, _, _ = select.select([process.stdout], [], [], 0.1)

      if ready:
        line = process.stdout.readline()
        if line:
          logger.info(f"BRIDGE traffic: {line.strip()}")
        else:
          break

      if process.poll() is not None:
        break

    if process.poll() is None:
      process.terminate()
      try:
        process.wait(timeout=2)
      except subprocess.TimeoutExpired:
        process.kill()

  except Exception as e:
    logger.error(f"Bridge monitor error: {e}")
  finally:
    logger.info("Bridge monitor stopped")

def check_network_status():
  """Check network interface status"""
  try:
    logger.info("=== NETWORK STATUS CHECK ===")

    # Check if interfaces exist and are up
    result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
    logger.info("Network interfaces:")
    for line in result.stdout.split('\n'):
      if 'tap0' in line or 'br0' in line:
        logger.info(f"  {line}")

    # Check bridge status
    result = subprocess.run(['ip', 'addr', 'show', BRIDGE_NAME],
                           capture_output=True, text=True, check=False)
    if result.returncode == 0:
      logger.info(f"Bridge {BRIDGE_NAME} status:")
      for line in result.stdout.split('\n'):
        if line.strip():
          logger.info(f"  {line}")

    # Check TAP status
    result = subprocess.run(['ip', 'addr', 'show', TAP_INTERFACE],
                           capture_output=True, text=True, check=False)
    if result.returncode == 0:
      logger.info(f"TAP {TAP_INTERFACE} status:")
      for line in result.stdout.split('\n'):
        if line.strip():
          logger.info(f"  {line}")

    # Check bridge membership
    result = subprocess.run(['bridge', 'link', 'show'],
                           capture_output=True, text=True, check=False)
    if result.returncode == 0:
      logger.info("Bridge membership:")
      for line in result.stdout.split('\n'):
        if line.strip():
          logger.info(f"  {line}")

    # Check routing table for our network
    result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, check=False)
    if result.returncode == 0:
      logger.info("Routing table (10.0.0.0/24 entries):")
      for line in result.stdout.split('\n'):
        if '10.0.0' in line:
          logger.info(f"  {line}")

    # Check active TCP connections on port 8080
    result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, check=False)
    if result.returncode == 0:
      logger.info("TCP connections on port 8080:")
      for line in result.stdout.split('\n'):
        if ':8080' in line:
          logger.info(f"  {line}")

    # Check iptables rules that might affect our traffic
    result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], capture_output=True, text=True, check=False)
    if result.returncode == 0:
      logger.info("Iptables INPUT rules:")
      for line in result.stdout.split('\n'):
        if 'tcp' in line and ('8080' in line or 'ACCEPT' in line):
          logger.info(f"  {line}")

    # Check if the HTTP server process is actually listening
    result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True, check=False)
    if result.returncode == 0:
      logger.info("Listening TCP sockets on port 8080:")
      for line in result.stdout.split('\n'):
        if ':8080' in line:
          logger.info(f"  {line}")

    logger.info("=== END NETWORK STATUS ===")

  except Exception as e:
    logger.error(f"Network status check error: {e}")

async def main():
  """Main async function"""
  logger.info("Starting control script...")

  # Initialize TAP interface with bridge
  tap = TAPInterface(TAP_INTERFACE)
  if not tap.create_tap():
    logger.error("Failed to create TAP interface. Make sure you have proper permissions.")
    return

  # Initialize UART server with TAP interface reference
  uart_server = UARTTCPServer(UART_TCP_PORT, tap)

  try:
    # Check network status first
    check_network_status()

    # Start HTTP server in a separate thread
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()

    # Give HTTP server time to start
    import time
    time.sleep(1)

    # Test HTTP server connectivity
    try:
      import urllib.request
      import urllib.error
      logger.info("Testing HTTP server connectivity...")

      # Test from localhost
      try:
        response = urllib.request.urlopen(f'http://localhost:{HTTP_PORT}/test', timeout=2)
        logger.info(f"✅ HTTP server reachable from localhost: {response.getcode()}")
      except Exception as e:
        logger.warning(f"❌ HTTP server NOT reachable from localhost: {e}")

      # Test from bridge IPs
      try:
        response = urllib.request.urlopen(f'http://10.0.0.1:{HTTP_PORT}/test', timeout=2)
        logger.info(f"✅ HTTP server reachable from 10.0.0.1: {response.getcode()}")
      except Exception as e:
        logger.warning(f"❌ HTTP server NOT reachable from 10.0.0.1: {e}")

      try:
        response = urllib.request.urlopen(f'http://10.0.0.2:{HTTP_PORT}/test', timeout=2)
        logger.info(f"✅ HTTP server reachable from 10.0.0.2: {response.getcode()}")
      except Exception as e:
        logger.warning(f"❌ HTTP server NOT reachable from 10.0.0.2: {e}")

    except Exception as e:
      logger.warning(f"HTTP connectivity test failed: {e}")

    # Start TAP traffic monitor in a separate thread
    traffic_thread = threading.Thread(target=run_traffic_monitor, daemon=True)
    traffic_thread.start()

    # Start bridge traffic monitor in a separate thread
    bridge_thread = threading.Thread(target=run_bridge_monitor, daemon=True)
    bridge_thread.start()

    # Start ARP responder in a separate thread
    if SCAPY_AVAILABLE:
      arp_thread = threading.Thread(target=arp_responder, daemon=True)
      arp_thread.start()
      logger.info("ARP responder started")
    else:
      logger.warning("ARP responder not started - install scapy for full functionality")

    # Start UART server
    await uart_server.start_server()

  except Exception as e:
    logger.error(f"Error in main: {e}")
  finally:
    # Cleanup
    uart_server.stop()
    tap.close()
    logger.info("Cleanup completed")

def signal_handler(signum, frame):
  """Handle Ctrl+C gracefully"""
  logger.info("Received interrupt signal, shutting down...")
  shutdown_event.set()

if __name__ == "__main__":
  # Set up signal handler for graceful shutdown
  signal.signal(signal.SIGINT, signal_handler)
  signal.signal(signal.SIGTERM, signal_handler)

  try:
    # Check if running as root (needed for TAP interface)
    if os.geteuid() != 0:
      logger.warning("Warning: Script not running as root. TAP interface creation may fail.")

    # Run the async main function
    asyncio.run(main())

  except KeyboardInterrupt:
    logger.info("Script interrupted by user")
  except Exception as e:
    logger.error(f"Unexpected error: {e}")
  finally:
    logger.info("Script terminated")
