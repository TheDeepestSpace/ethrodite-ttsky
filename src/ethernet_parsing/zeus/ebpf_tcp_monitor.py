#!/usr/bin/env python3
"""
XDP/eBPF packet interceptor for TCP SYN packets
This requires bcc/eBPF support
"""
try:
    from bcc import BPF
    BPF_AVAILABLE = True
except ImportError:
    BPF_AVAILABLE = False

import logging
import socket
import struct

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# eBPF program to intercept TCP packets
BPF_PROGRAM = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_PERF_OUTPUT(events);

struct tcp_event {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 flags;
};

int tcp_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
        
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
        
    struct iphdr *ip = (void*)eth + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end)
        return XDP_PASS;
        
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
        
    struct tcphdr *tcp = (void*)ip + sizeof(*ip);
    if ((void*)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;
        
    // Check if it's destined for port 8080 or 9999
    u16 dst_port = ntohs(tcp->dest);
    if (dst_port != 8080 && dst_port != 9999)
        return XDP_PASS;
        
    struct tcp_event evt = {};
    evt.src_ip = ip->saddr;
    evt.dst_ip = ip->daddr; 
    evt.src_port = ntohs(tcp->source);
    evt.dst_port = dst_port;
    evt.flags = ((u8*)tcp)[13]; // TCP flags
    
    events.perf_submit(ctx, &evt, sizeof(evt));
    
    return XDP_PASS;  // Let packet continue
}
"""

def handle_tcp_event(cpu, data, size):
    """Handle TCP events from eBPF"""
    event = struct.unpack("LLHBB", data[:13])
    src_ip = socket.inet_ntoa(struct.pack("L", event[0]))
    dst_ip = socket.inet_ntoa(struct.pack("L", event[1]))
    src_port = event[2]
    dst_port = event[3]
    flags = event[4]
    
    logger.info(f"🎯 eBPF intercepted TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    logger.info(f"   Flags: {flags:02x} ({'SYN' if flags & 0x02 else ''} {'ACK' if flags & 0x10 else ''})")
    
    if flags & 0x02 and not (flags & 0x10):  # SYN but not ACK
        logger.info("📥 TCP SYN detected - this packet SHOULD reach userspace but doesn't!")

def main():
    if not BPF_AVAILABLE:
        logger.error("BCC/eBPF not available. Install with: sudo apt install python3-bpfcc")
        return
        
    try:
        logger.info("🔧 Loading eBPF program...")
        b = BPF(text=BPF_PROGRAM)
        
        # Attach to bridge interface
        fn = b.load_func("tcp_monitor", BPF.XDP)
        b.attach_xdp("br0", fn, 0)
        
        logger.info("🔍 eBPF TCP monitor attached to br0")
        logger.info("Monitoring TCP packets to ports 8080 and 9999...")
        
        # Set up event handler
        b["events"].open_perf_buffer(handle_tcp_event)
        
        while True:
            b.perf_buffer_poll()
            
    except Exception as e:
        logger.error(f"eBPF error: {e}")
        logger.info("eBPF requires root privileges and kernel support")

if __name__ == "__main__":
    main()
