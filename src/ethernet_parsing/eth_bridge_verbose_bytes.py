#!/usr/bin/env python3
"""
eth_bridge_verbose_bytes.py

Bridge that sniffs/generates Ethernet frames, forwards to a TCP server, and prints
a detailed byte-level breakdown for each packet's L2/L3/L4 headers and payload.

Usage (examples):
  python eth_bridge_verbose_bytes.py --tb-ip tcpbin.com --tb-port 4242 --raw --no-inject --dump --generate-count 5
"""

import argparse, socket, struct, threading, time, binascii, os, sys
from scapy.all import sniff, Ether, IP, TCP, Raw, get_if_list, get_if_hwaddr, sendp
from scapy.utils import PcapWriter

# -----------------------------
# CLI
# -----------------------------
parser = argparse.ArgumentParser(description="Verbose Ethernet↔TCP bridge (byte-level prints)")
parser.add_argument("--tb-ip", required=True)
parser.add_argument("--tb-port", type=int, required=True)
parser.add_argument("--raw", action="store_true", help="Send/receive raw bytes (no 2-byte length prefix)")
parser.add_argument("--no-inject", action="store_true", help="Do not inject received frames to NIC")
parser.add_argument("--dump", action="store_true", help="Dump frames to logs/*.pcap")
parser.add_argument("--iface", help="Interface to use (auto-detect by default)")
parser.add_argument("--retries", type=int, default=5, help="Connection attempts")
parser.add_argument("--retry-delay", type=float, default=1.0, help="Seconds between connect attempts")
parser.add_argument("--generate-count", type=int, default=0, help="If >0, generate N synthetic frames")
parser.add_argument("--generate-interval", type=float, default=1.0, help="Seconds between generated frames")
parser.add_argument("--generate-src", default="11:22:33:44:55:66", help="Eth src MAC for generated frames")
parser.add_argument("--generate-dst", default="aa:bb:cc:dd:ee:ff", help="Eth dst MAC for generated frames")
parser.add_argument("--generate-payload", default="SYNTH", help="Payload string for generated frames")
args = parser.parse_args()

# -----------------------------
# Interface selection
# -----------------------------
def select_wired_interface():
    interfaces = get_if_list()
    for iface in interfaces:
        name = iface.lower()
        if "loopback" in name or "wi-fi" in name or "wifi" in name or "wireless" in name or name.startswith("lo"):
            continue
        try:
            mac = get_if_hwaddr(iface)
            if mac != "00:00:00:00:00:00":
                return iface, mac
        except Exception:
            continue
    raise RuntimeError("No wired Ethernet interface found. Use --iface to specify one.")

if args.iface:
    INTERFACE = args.iface
    try:
        MAC = get_if_hwaddr(INTERFACE)
    except Exception as e:
        print("Error getting MAC for iface:", e)
        sys.exit(1)
else:
    INTERFACE, MAC = select_wired_interface()

print(f"[+] Using interface: {INTERFACE} (MAC {MAC})")
print(f"[+] Target server: {args.tb_ip}:{args.tb_port}  (raw={args.raw}, no_inject={args.no_inject}, dump={args.dump})")
if args.generate_count > 0:
    print(f"[+] Synthetic generator enabled: count={args.generate_count} interval={args.generate_interval}s src={args.generate_src} dst={args.generate_dst}")

# -----------------------------
# Optional pcap dump
# -----------------------------
pcap_tx = pcap_rx = None
if args.dump:
    os.makedirs("logs", exist_ok=True)
    try:
        pcap_tx = PcapWriter("logs/to_server.pcap", append=True, sync=True)
        pcap_rx = PcapWriter("logs/from_server.pcap", append=True, sync=True)
        print("[*] Dumping frames to logs/to_server.pcap and logs/from_server.pcap")
    except Exception as e:
        print("[-] Could not create pcap writers:", e)
        args.dump = False

# -----------------------------
# Helpers: hex formatting & parsing
# -----------------------------
def hexstr(b):
    return " ".join([f"{x:02x}" for x in b])

def pretty_print_packet(raw_bytes, tag="PACKET"):
    """
    Print detailed breakdown: Ethernet header bytes/fields, IP header bytes/fields,
    TCP header bytes/fields, payload bytes.
    """
    print(f"\n[{tag}] full len={len(raw_bytes)} bytes")
    if not raw_bytes:
        print(f"[{tag}] EMPTY")
        return

    # Attempt L2 parse
    try:
        eth = Ether(raw_bytes)
    except Exception as e:
        print(f"[{tag}] Could not parse as Ether: {e}; raw: {hexstr(raw_bytes)}")
        return

    # Ethernet header raw bytes (14 bytes normally)
    try:
        eth_hdr_len = 14
        eth_hdr = raw_bytes[:eth_hdr_len]
    except Exception:
        eth_hdr = b""

    print(f"[{tag}] Ethernet header ({len(eth_hdr)} bytes): {hexstr(eth_hdr)}")
    print(f"[{tag}]   dst={eth.dst} src={eth.src} type=0x{eth.type:04x}")

    # IPv4
    if eth.type == 0x0800 and IP in eth:
        ip_layer = eth[IP]
        ihl_bytes = ip_layer.ihl * 4
        ip_hdr = raw_bytes[eth_hdr_len:eth_hdr_len + ihl_bytes]
        print(f"[{tag}] IPv4 header ({len(ip_hdr)} bytes): {hexstr(ip_hdr)}")
        print(f"[{tag}]   src={ip_layer.src} dst={ip_layer.dst} ver={ip_layer.version} ihl={ip_layer.ihl} tot_len={ip_layer.len} proto={ip_layer.proto} ttl={ip_layer.ttl} id={ip_layer.id} checksum=0x{ip_layer.chksum:04x}")

        # TCP
        if ip_layer.proto == 6 and TCP in ip_layer:
            tcp_layer = ip_layer[TCP]
            tcp_hdr_len = tcp_layer.dataofs * 4
            tcp_hdr_start = eth_hdr_len + ihl_bytes
            tcp_hdr = raw_bytes[tcp_hdr_start:tcp_hdr_start + tcp_hdr_len]
            print(f"[{tag}] TCP header ({len(tcp_hdr)} bytes): {hexstr(tcp_hdr)}")
            flags = []
            if tcp_layer.flags & 0x02: flags.append("SYN")
            if tcp_layer.flags & 0x10: flags.append("ACK")
            if tcp_layer.flags & 0x01: flags.append("FIN")
            if tcp_layer.flags & 0x04: flags.append("RST")
            if tcp_layer.flags & 0x08: flags.append("PSH")
            if tcp_layer.flags & 0x20: flags.append("URG")
            print(f"[{tag}]   sport={tcp_layer.sport} dport={tcp_layer.dport} seq={tcp_layer.seq} ack={tcp_layer.ack} flags={'|'.join(flags) or 'NONE'} window={tcp_layer.window} checksum=0x{tcp_layer.chksum:04x} options={tcp_layer.options}")

            # payload
            payload_start = tcp_hdr_start + tcp_hdr_len
            payload = raw_bytes[payload_start:]
            if payload:
                print(f"[{tag}] Payload ({len(payload)} bytes): {hexstr(payload)}")
            else:
                print(f"[{tag}] Payload: <none>")
            return

        # Non-TCP transport (UDP/ICMP/other)
        payload_start = eth_hdr_len + ihl_bytes
        payload = raw_bytes[payload_start:]
        if payload:
            print(f"[{tag}] L4 payload ({len(payload)} bytes): {hexstr(payload)}")
        else:
            print(f"[{tag}] L4 payload: <none>")
        return

    # Non-IPv4 or cannot parse IP
    payload = raw_bytes[len(eth_hdr):]
    if payload:
        print(f"[{tag}] L2 payload ({len(payload)} bytes): {hexstr(payload)}")
    else:
        print(f"[{tag}] No L2 payload")

# -----------------------------
# Networking helpers
# -----------------------------
def recv_all(sock, length):
    buf = b""
    while len(buf) < length:
        try:
            chunk = sock.recv(length - len(buf))
        except socket.timeout:
            continue
        if not chunk:
            return buf
        buf += chunk
    return buf

def connect_with_retries(host, port, attempts, delay):
    last_err = None
    for i in range(1, attempts+1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((host, port))
            s.settimeout(1.0)
            return s
        except Exception as e:
            last_err = e
            print(f"[-] Connect attempt {i} failed: {e}")
            try:
                s.close()
            except Exception:
                pass
            time.sleep(delay)
    raise last_err

try:
    conn = connect_with_retries(args.tb_ip, args.tb_port, args.retries, args.retry_delay)
except Exception as e:
    print("[-] Could not connect to server, exiting:", e)
    sys.exit(1)

print("[+] Connected to server.")

stop_evt = threading.Event()
pcap_lock = threading.Lock()

# -----------------------------
# Sniff -> send to server (with verbose print)
# -----------------------------
def send_to_server(pkt):
    if stop_evt.is_set():
        return False
    try:
        raw = bytes(pkt)
    except Exception:
        return
    if not raw:
        return
    # Print breakdown before sending
    pretty_print_packet(raw, tag="→ SERVER (sniffed)")
    try:
        if args.raw:
            conn.sendall(raw)
        else:
            if len(raw) > 0xFFFF:
                print("[-] Packet too large for 2-byte prefix; skipping.")
                return
            conn.sendall(struct.pack(">H", len(raw)) + raw)
        if args.dump and pcap_tx is not None:
            try:
                with pcap_lock:
                    pcap_tx.write(Ether(raw))
            except Exception:
                pass
    except Exception as e:
        print("[-] send_to_server error:", e)
        stop_evt.set()

def sniff_thread():
    print(f"[*] Starting sniff on interface {INTERFACE} ...")
    sniff(iface=INTERFACE, prn=send_to_server, store=False, stop_filter=lambda x: stop_evt.is_set())

sniff_t = threading.Thread(target=sniff_thread, daemon=True)
sniff_t.start()

# -----------------------------
# Receive from server -> print/detail/inject
# -----------------------------
def recv_from_server():
    try:
        while not stop_evt.is_set():
            try:
                if args.raw:
                    try:
                        data = conn.recv(65536)
                    except socket.timeout:
                        continue
                    if not data:
                        print("[*] Server closed connection")
                        stop_evt.set()
                        break
                    print(f"\n[← SERVER raw] Received {len(data)} bytes")
                    # try to parse as Ethernet frames — might be multiple frames concatenated
                    # attempt to split if multiple valid Ether frames: naive conservative approach:
                    # try parsing full buffer as one Ether; if fails, just show raw
                    try:
                        pretty_print_packet(data, tag="← SERVER (received)")
                        if args.dump and pcap_rx is not None and len(data) >= 14:
                            with pcap_lock:
                                pcap_rx.write(Ether(data))
                    except Exception:
                        print("[← SERVER raw] (unparsable as Ether) raw bytes:", hexstr(data))
                else:
                    try:
                        hdr = conn.recv(2)
                    except socket.timeout:
                        continue
                    if not hdr:
                        print("[*] Server closed connection")
                        stop_evt.set()
                        break
                    if len(hdr) < 2:
                        more = recv_all(conn, 2 - len(hdr))
                        if not more:
                            print("[*] Server closed while reading header")
                            stop_evt.set()
                            break
                        hdr += more
                    length = struct.unpack(">H", hdr)[0]
                    if length == 0:
                        print("[<- SERVER] Received empty frame (len=0)")
                        continue
                    frame = recv_all(conn, length)
                    if len(frame) < length:
                        print("[-] Server closed before full frame arrived")
                        stop_evt.set()
                        break
                    pretty_print_packet(frame, tag="← SERVER (framed)")
                    if args.dump and pcap_rx is not None and len(frame) >= 14:
                        try:
                            with pcap_lock:
                                pcap_rx.write(Ether(frame))
                        except Exception:
                            pass
                    if not args.no_inject:
                        try:
                            sendp(Ether(frame), iface=INTERFACE, verbose=False)
                            print(f"[<INJECT] injected frame ({length} bytes)")
                        except Exception as e:
                            print("[-] Injection failed:", e)
            except Exception as e:
                if isinstance(e, OSError):
                    break
                print("[-] recv_from_server iteration error:", e)
                stop_evt.set()
                break
    finally:
        print("[*] recv_from_server exiting")

recv_t = threading.Thread(target=recv_from_server, daemon=True)
recv_t.start()

# -----------------------------
# Synthetic generator (prints too)
# -----------------------------
def synthetic_generator_thread(count, interval, src_mac, dst_mac, payload_str):
    print(f"[*] Synthetic generator running: count={count}, interval={interval}s")
    for i in range(count):
        if stop_evt.is_set():
            break
        payload = f"{payload_str}-{i}".encode()
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src="192.0.2.2", dst="192.0.2.1") / TCP(sport=10000 + i, dport=80, seq=1000 + i) / Raw(load=payload)
        raw = bytes(pkt)
        # send onto NIC (so sniff thread picks it up and forwards)
        try:
            sendp(pkt, iface=INTERFACE, verbose=False)
            print(f"[GEN] generated frame #{i} len={len(raw)} preview={hexstr(raw[:40])} ... ({len(raw)} bytes)")
            # also print breakdown for generator-local visibility
            pretty_print_packet(raw, tag=f"GEN #{i}")
        except Exception as e:
            print("[-] Generator sendp failed:", e)
        time.sleep(interval)
    print("[*] Synthetic generator finished")

gen_t = None
if args.generate_count > 0:
    gen_t = threading.Thread(target=synthetic_generator_thread, args=(args.generate_count, args.generate_interval, args.generate_src, args.generate_dst, args.generate_payload), daemon=True)
    gen_t.start()

# -----------------------------
# Main loop
# -----------------------------
print("[*] Bridge running. Press Ctrl+C to stop.")
try:
    while not stop_evt.is_set():
        stop_evt.wait(1)
except KeyboardInterrupt:
    print("[*] Ctrl+C detected, stopping...")
    stop_evt.set()

# cleanup
try:
    conn.close()
except Exception:
    pass

if args.dump and pcap_tx:
    try:
        pcap_tx.close()
        pcap_rx.close()
    except Exception:
        pass

print("[+] Bridge stopped cleanly.")
