// ============================================================================
// File: ethernet_info.svh
// Description: Unified Ethernet + IPv4 header layout macros
// Author: rob + GPT-5
// Version: 2.0
// ----------------------------------------------------------------------------
// Defines offsets, field sizes, and constants for Ethernet and IPv4 header
// parsing in FPGA streaming designs (AXI-Stream).
// ============================================================================

`ifndef ETHERNET_INFO_SVH
`define ETHERNET_INFO_SVH

`define INPUTWIDTH              64

`define AXI_BYTES(DATA_WIDTH) ((DATA_WIDTH)/8)

// -----------------------------------------------------------------------------
// Ethernet Header (14 bytes)
// -----------------------------------------------------------------------------
`define ETH_HEADER_BYTES          14
`define ETH_DST_MAC_BASE          0
`define ETH_SRC_MAC_BASE          6
`define ETH_TYPE_BASE             12
`define CRC32_WIDTH               4

// Per-byte Ethernet fields
`define ETH_DST_MAC_0 (`ETH_DST_MAC_BASE + 0)
`define ETH_DST_MAC_1 (`ETH_DST_MAC_BASE + 1)
`define ETH_DST_MAC_2 (`ETH_DST_MAC_BASE + 2)
`define ETH_DST_MAC_3 (`ETH_DST_MAC_BASE + 3)
`define ETH_DST_MAC_4 (`ETH_DST_MAC_BASE + 4)
`define ETH_DST_MAC_5 (`ETH_DST_MAC_BASE + 5)

`define ETH_SRC_MAC_0 (`ETH_SRC_MAC_BASE + 0)
`define ETH_SRC_MAC_1 (`ETH_SRC_MAC_BASE + 1)
`define ETH_SRC_MAC_2 (`ETH_SRC_MAC_BASE + 2)
`define ETH_SRC_MAC_3 (`ETH_SRC_MAC_BASE + 3)
`define ETH_SRC_MAC_4 (`ETH_SRC_MAC_BASE + 4)
`define ETH_SRC_MAC_5 (`ETH_SRC_MAC_BASE + 5)

`define ETH_TYPE_MSB_OFFSET (`ETH_TYPE_BASE + 0)
`define ETH_TYPE_LSB_OFFSET (`ETH_TYPE_BASE + 1)

// Common Ethertypes
`define ETH_TYPE_IPV4 16'h0800
`define ETH_TYPE_ARP  16'h0806
`define ETH_TYPE_IPV6 16'h86DD


// -----------------------------------------------------------------------------
// IPv4 Header (20 bytes minimum, 60 max)
// -----------------------------------------------------------------------------
`define IPV4_HEADER_BYTES         20
`define IPV4_HEADER_MIN_BYTES     20
`define IPV4_HEADER_MAX_BYTES     60
`define IPV4_HEADER_BASE          (`ETH_HEADER_BYTES)

// Relative offsets (from start of IPv4 header)
`define IPV4_VERSION_IHL_OFFSET       0
`define IPV4_DSCP_ECN_OFFSET          1
`define IPV4_TOTAL_LENGTH_MSB_OFFSET  2
`define IPV4_TOTAL_LENGTH_LSB_OFFSET  3
`define IPV4_IDENT_MSB_OFFSET         4
`define IPV4_IDENT_LSB_OFFSET         5
`define IPV4_FLAGS_FRAG_MSB_OFFSET    6
`define IPV4_FLAGS_FRAG_LSB_OFFSET    7
`define IPV4_TTL_OFFSET               8
`define IPV4_PROTOCOL_OFFSET          9
`define IPV4_CHECKSUM_MSB_OFFSET      10
`define IPV4_CHECKSUM_LSB_OFFSET      11
`define IPV4_SRC_IP_OFFSET            12
`define IPV4_DST_IP_OFFSET            16

// Expanded byte addressing (optional)
`define IPV4_SRC_IP_0 (`IPV4_SRC_IP_OFFSET + 0)
`define IPV4_SRC_IP_1 (`IPV4_SRC_IP_OFFSET + 1)
`define IPV4_SRC_IP_2 (`IPV4_SRC_IP_OFFSET + 2)
`define IPV4_SRC_IP_3 (`IPV4_SRC_IP_OFFSET + 3)
`define IPV4_DST_IP_0 (`IPV4_DST_IP_OFFSET + 0)
`define IPV4_DST_IP_1 (`IPV4_DST_IP_OFFSET + 1)
`define IPV4_DST_IP_2 (`IPV4_DST_IP_OFFSET + 2)
`define IPV4_DST_IP_3 (`IPV4_DST_IP_OFFSET + 3)

// Absolute positions (Ethernet + IPv4)
`define IPV4_VERSION_IHL_ABS       (`ETH_HEADER_BYTES + `IPV4_VERSION_IHL_OFFSET)
`define IPV4_TOTAL_LENGTH_ABS      (`ETH_HEADER_BYTES + `IPV4_TOTAL_LENGTH_MSB_OFFSET)
`define IPV4_SRC_IP_ABS            (`ETH_HEADER_BYTES + `IPV4_SRC_IP_OFFSET)
`define IPV4_DST_IP_ABS            (`ETH_HEADER_BYTES + `IPV4_DST_IP_OFFSET)

// -----------------------------------------------------------------------------
// IPv4 Field Constants
// -----------------------------------------------------------------------------
`define IPV4_VERSION_DEFAULT       4'h4
`define IPV4_IHL_DEFAULT           4'h5
`define IPV4_PROTOCOL_ICMP         8'd1
`define IPV4_PROTOCOL_TCP          8'd6
`define IPV4_PROTOCOL_UDP          8'd17

// -----------------------------------------------------------------------------
// IPv4 Header Checksum Constants
// -----------------------------------------------------------------------------
`define IPV4_CSUM_WORD_WIDTH       16
`define IPV4_CSUM_ACCUM_WIDTH      32
`define IPV4_CSUM_OK_VALUE         16'hFFFF

// -----------------------------------------------------------------------------
// Combined Header Constants
// -----------------------------------------------------------------------------
`define ETH_IPV4_HEADER_BYTES      (`ETH_HEADER_BYTES + `IPV4_HEADER_BYTES)
`define MAC_ADDR_BYTES             6
`define IPV4_ADDR_BYTES            4

//TCP 
`define IPV4_TCP_PROTO 8'd6

`define TCP_SRC_PORT_BASE         0     // 16 bits
`define TCP_DST_PORT_BASE         2     // 16 bits
`define TCP_SEQ_NUM_BASE          4     // 32 bits
`define TCP_ACK_NUM_BASE          8     // 32 bits
`define TCP_DATA_OFFSET_BASE      12    // upper 4 bits of this byte
`define TCP_FLAGS_BASE            13    // 6 bits of flags (plus 2 reserved bits)
`define TCP_WINDOW_SIZE_BASE      14    // 16 bits
`define TCP_CHECKSUM_BASE         16    // 16 bits
`define TCP_URGENT_PTR_BASE       18    // 16 bits
`define TCP_HEADER_MIN_LEN        20    // bytes (without options)

`define TCP_FLAG_CWR  7
`define TCP_FLAG_ECE  6
`define TCP_FLAG_URG  5
`define TCP_FLAG_ACK  4
`define TCP_FLAG_PSH  3
`define TCP_FLAG_RST  2
`define TCP_FLAG_SYN  1
`define TCP_FLAG_FIN  0

`endif // ETHERNET_INFO_SVH
