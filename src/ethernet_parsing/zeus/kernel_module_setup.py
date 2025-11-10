#!/usr/bin/env python3
"""
Instructions and helper for creating a simple kernel module TCP interceptor
This is the most direct way to intercept packets at kernel level
"""

KERNEL_MODULE_C = '''
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

static struct nf_hook_ops nfho;

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    if (!skb)
        return NF_ACCEPT;
        
    iph = ip_hdr(skb);
    
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        
        // Check if destined for our ports
        if (ntohs(tcph->dest) == 8080 || ntohs(tcph->dest) == 9999) {
            printk(KERN_INFO "TCP_INTERCEPT: %pI4:%u -> %pI4:%u flags=0x%02x\\n",
                   &iph->saddr, ntohs(tcph->source),
                   &iph->daddr, ntohs(tcph->dest),
                   tcph->syn << 1 | tcph->ack);
        }
    }
    
    return NF_ACCEPT;
}

static int __init tcp_intercept_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "TCP interceptor loaded\\n");
    return 0;
}

static void __exit tcp_intercept_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "TCP interceptor unloaded\\n");
}

module_init(tcp_intercept_init);
module_exit(tcp_intercept_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Packet Interceptor");
'''

MAKEFILE = '''
obj-m := tcp_intercept.o

KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod tcp_intercept.ko

uninstall:
	sudo rmmod tcp_intercept

logs:
	dmesg | grep TCP_INTERCEPT
'''

import logging
import os
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_kernel_module():
    """Create kernel module files"""
    try:
        # Create tcp_intercept.c
        with open('tcp_intercept.c', 'w') as f:
            f.write(KERNEL_MODULE_C)
        
        # Create Makefile
        with open('Makefile', 'w') as f:
            f.write(MAKEFILE)
            
        logger.info("✅ Kernel module files created: tcp_intercept.c, Makefile")
        logger.info("📋 To build and install:")
        logger.info("   make")
        logger.info("   sudo make install")
        logger.info("   sudo make logs  # View intercepted packets")
        logger.info("   sudo make uninstall  # When done")
        
    except Exception as e:
        logger.error(f"Error creating kernel module: {e}")

def main():
    logger.info("🔧 Kernel Module TCP Interceptor Setup")
    logger.info("This creates a kernel module that intercepts TCP packets directly")
    
    create_kernel_module()

if __name__ == "__main__":
    main()
