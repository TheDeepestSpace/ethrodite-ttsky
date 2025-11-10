`timescale 1ns/1ps
`include "ethernet_info.svh"
`include "crc32.sv"
`include "axi_stream_if.sv"

`ifndef TCP_PACKET_INFO_S_SV
`define TCP_PACKET_INFO_S_SV
typedef struct packed {
    logic [47:0] src_mac;
    logic [47:0] dst_mac;
    logic [31:0] src_ip;
    logic [31:0] dst_ip;
    logic [15:0] src_port;
    logic [15:0] dst_port;
    logic [31:0] seq_num;
    logic [31:0] ack_num;
    logic [7:0]  tcp_flags;
    logic [15:0] window;
    logic [15:0] payload_len;
    logic [15:0] tcp_checksum; // if payload present
} tcp_packet_info_s;
`endif

module tcp_sender #(
    parameter int DATA_WIDTH = `INPUTWIDTH
)(
    input  logic clk,
    input  logic rst_n,
    input  logic start,
    input  tcp_packet_info_s i_pkt,
    axi_stream_if.slave  s_axis,
    axi_stream_if.master m_axis,
    output logic busy
);

    // ------------------------------------------------------------
    // Local parameters
    // ------------------------------------------------------------
    localparam int ETH_HEADER_BYTES  = `ETH_HEADER_BYTES;
    localparam int IPV4_HEADER_BYTES = `IPV4_HEADER_BYTES;
    localparam int TCP_HEADER_BYTES  = 20;
    localparam int HEADER_BYTES      = ETH_HEADER_BYTES + IPV4_HEADER_BYTES + TCP_HEADER_BYTES;

    typedef enum logic [2:0] {
        ST_IDLE,
        ST_SEND_HDR,
        ST_SEND_PAYLOAD,
        ST_SEND_CRC
    } state_e;

    // ------------------------------------------------------------
    // Registers
    // ------------------------------------------------------------
    state_e state, state_n;
    tcp_packet_info_s pkt_r, pkt_n;

    logic [15:0] byte_cnt_r, byte_cnt_n;
    logic [31:0] crc32_r, crc32_n;

    // TCP checksum accumulation
    logic [31:0] tcp_sum32_r, tcp_sum32_n, ipv4_sum32_r, ipv4_sum32_n;

    logic [7:0] odd_byte_r, odd_byte_n;

    function automatic logic [15:0] fold_checksum(input logic [31:0] sum32_r);
        logic [31:0] folded;
        folded = (sum32_r & 16'hFFFF) + (sum32_r >> 16);
        folded = (folded & 16'hFFFF) + (folded >> 16);
        return ~folded[15:0];
    endfunction

    assign busy = (state != ST_IDLE);
    assign s_axis.tready = (state == ST_SEND_PAYLOAD) && m_axis.tready;

    // ------------------------------------------------------------
    // Output logic
    // ------------------------------------------------------------
    always_comb begin
        automatic logic [15:0] tcp_chksum = fold_checksum(tcp_sum32_r);
        automatic logic [15:0] ipv4_chksum = fold_checksum(ipv4_sum32_r);

        m_axis.tvalid = 0;
        m_axis.tlast  = 0;
        m_axis.tdata  = '0;
        byte_cnt_n    = byte_cnt_r;
        state_n       = state;
        crc32_n = crc32_r;
        odd_byte_n = odd_byte_r;
        ipv4_sum32_n = ipv4_sum32_r;
        tcp_sum32_n = tcp_sum32_r;
        pkt_n = pkt_r;

        case (state)
            ST_IDLE: begin
                if (start) begin
                    pkt_n       = i_pkt;
                    byte_cnt_n  = 0;
                    crc32_n     = 32'hFFFFFFFF;
                    tcp_sum32_n = i_pkt.tcp_checksum + (`IPV4_TCP_PROTO<<8)+i_pkt.payload_len+TCP_HEADER_BYTES;
                    ipv4_sum32_n = '0;
                    //odd_byte_n = '0;
                    state_n     = ST_SEND_HDR;
                end
            end

            // ----------------------------------------------------
            // Stream out header bytes directly
            // ----------------------------------------------------
            ST_SEND_HDR: begin
                if (m_axis.tready) begin
                    automatic logic [15:0] ipv4_word;
                    m_axis.tvalid = 1;

                    case (byte_cnt_r)
                        0:  ipv4_word = {8'h45, 8'h00};  // Version/IHL + DSCP/ECN
                        1:  ipv4_word = { 
                                8'((IPV4_HEADER_BYTES + TCP_HEADER_BYTES + pkt_r.payload_len) >> 8),
                                8'((IPV4_HEADER_BYTES + TCP_HEADER_BYTES + pkt_r.payload_len) & 8'hFF)
                            }; // Total length
                        2:  ipv4_word = 16'h0000;         // Identification
                        3:  ipv4_word = 16'h4000;         // Flags + Fragment offset
                        4:  ipv4_word = 16'h4006;         // TTL + Protocol (TCP)
                        5:  ipv4_word = 16'h0000;         // Header checksum (placeholder)
                        6:  ipv4_word = pkt_r.src_ip[31:16]; // Src IP upper half
                        7:  ipv4_word = pkt_r.src_ip[15:0];  // Src IP lower half
                        8:  ipv4_word = pkt_r.dst_ip[31:16]; // Dst IP upper half
                        9:  ipv4_word = pkt_r.dst_ip[15:0];  // Dst IP lower half
                        default: ipv4_word = 16'h0000;
                    endcase                    
                    ipv4_sum32_n = ipv4_sum32_n + ipv4_word;

                    case (byte_cnt_r)
                        // --- Ethernet header ---
                        0:  m_axis.tdata = pkt_r.dst_mac[47:40];
                        1:  m_axis.tdata = pkt_r.dst_mac[39:32];
                        2:  m_axis.tdata = pkt_r.dst_mac[31:24];
                        3:  m_axis.tdata = pkt_r.dst_mac[23:16];
                        4:  m_axis.tdata = pkt_r.dst_mac[15:8];
                        5:  m_axis.tdata = pkt_r.dst_mac[7:0];
                        6:  m_axis.tdata = pkt_r.src_mac[47:40];
                        7:  m_axis.tdata = pkt_r.src_mac[39:32];
                        8:  m_axis.tdata = pkt_r.src_mac[31:24];
                        9:  m_axis.tdata = pkt_r.src_mac[23:16];
                        10: m_axis.tdata = pkt_r.src_mac[15:8];
                        11: m_axis.tdata = pkt_r.src_mac[7:0];
                        12: m_axis.tdata = 8'h08;
                        13: m_axis.tdata = 8'h00;

                        // --- IPv4 header ---
                        14: m_axis.tdata = 8'h45;
                        15: m_axis.tdata = 8'h00;
                        16: m_axis.tdata = ((IPV4_HEADER_BYTES + TCP_HEADER_BYTES + pkt_r.payload_len) >> 8);
                        17: m_axis.tdata = ((IPV4_HEADER_BYTES + TCP_HEADER_BYTES + pkt_r.payload_len) & 8'hFF);
                        18: m_axis.tdata = 8'h00;
                        19: m_axis.tdata = 8'h00;
                        20: m_axis.tdata = 8'h40;
                        21: m_axis.tdata = 8'h00;
                        22: m_axis.tdata = 8'h40;
                        23: m_axis.tdata = 8'h06;
                        24: m_axis.tdata = ipv4_chksum[15:8]; // IPv4 checksum placeholder
                        25: m_axis.tdata = ipv4_chksum[7:0];
                        26: m_axis.tdata = pkt_r.src_ip[31:24];
                        27: m_axis.tdata = pkt_r.src_ip[23:16];
                        28: m_axis.tdata = pkt_r.src_ip[15:8];
                        29: m_axis.tdata = pkt_r.src_ip[7:0];
                        30: m_axis.tdata = pkt_r.dst_ip[31:24];
                        31: m_axis.tdata = pkt_r.dst_ip[23:16];
                        32: m_axis.tdata = pkt_r.dst_ip[15:8];
                        33: m_axis.tdata = pkt_r.dst_ip[7:0];

                        // --- TCP header ---
                        34: m_axis.tdata = pkt_r.src_port[15:8];
                        35: m_axis.tdata = pkt_r.src_port[7:0];
                        36: m_axis.tdata = pkt_r.dst_port[15:8];
                        37: m_axis.tdata = pkt_r.dst_port[7:0];
                        38: m_axis.tdata = pkt_r.seq_num[31:24];
                        39: m_axis.tdata = pkt_r.seq_num[23:16];
                        40: m_axis.tdata = pkt_r.seq_num[15:8];
                        41: m_axis.tdata = pkt_r.seq_num[7:0];
                        42: m_axis.tdata = pkt_r.ack_num[31:24];
                        43: m_axis.tdata = pkt_r.ack_num[23:16];
                        44: m_axis.tdata = pkt_r.ack_num[15:8];
                        45: m_axis.tdata = pkt_r.ack_num[7:0];
                        46: m_axis.tdata = 8'h50; // data offset 5 words
                        47: m_axis.tdata = pkt_r.tcp_flags;
                        48: m_axis.tdata = pkt_r.window[15:8];
                        49: m_axis.tdata = pkt_r.window[7:0];
                        50: m_axis.tdata = tcp_chksum[15:8]; // filled inline
                        51: m_axis.tdata = tcp_chksum[7:0];
                        52: m_axis.tdata = 8'h00;
                        53: m_axis.tdata = 8'h00;
                        default: m_axis.tdata = 8'h00;
                    endcase

                    crc32_n = crc(crc32_n, m_axis.tdata);
                    if (byte_cnt_r == HEADER_BYTES-1) begin
                        byte_cnt_n = 0;
                        if (pkt_r.payload_len == 0) begin
                            state_n = ST_SEND_CRC;
                            crc32_n = ~crc32_n;
                        end else
                            state_n = ST_SEND_PAYLOAD;
                    end else
                        byte_cnt_n = byte_cnt_n + 1;

                    if (byte_cnt_r >= 26 && byte_cnt_r <= 49) begin
                        if (byte_cnt_r[0] == 1'b1)
                            tcp_sum32_n += {odd_byte_r, m_axis.tdata};
                        else
                            odd_byte_n = m_axis.tdata;
                    end
                end
            end

            // ----------------------------------------------------
            // Stream payload directly from s_axis
            // ----------------------------------------------------
            ST_SEND_PAYLOAD: begin
                if (s_axis.tvalid && m_axis.tready) begin
                    m_axis.tvalid = 1;
                    m_axis.tdata  = s_axis.tdata;
                    crc32_n = crc(crc32_n, s_axis.tdata);
                    if (s_axis.tlast || byte_cnt_r == pkt_r.payload_len-1) begin
                        state_n = ST_SEND_CRC;
                        byte_cnt_n = 0;
                        crc32_n = ~crc32_n;
                    end
                    else
                        byte_cnt_n = byte_cnt_n + 1;
                end
            end

            // ----------------------------------------------------
            // Transmit CRC32
            // ----------------------------------------------------
            ST_SEND_CRC: begin
                if (m_axis.tready) begin
                    m_axis.tvalid = 1;
                    m_axis.tdata  = crc32_r[8*byte_cnt_r[1:0] +: 8];
                    m_axis.tlast  = (byte_cnt_r[1:0] == 2'd3);
                    if (byte_cnt_r[1:0] == 2'd3) begin
                        state_n = ST_IDLE;
                        byte_cnt_n = 0;
                    end
                    else begin
                        byte_cnt_n    = byte_cnt_r + 1;
                    end
                end
            end

            default: state_n = ST_IDLE;
        endcase
    end

    // ------------------------------------------------------------
    // Sequential registers
    // ------------------------------------------------------------
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= ST_IDLE;
            crc32_r    <= 32'hFFFFFFFF;
            tcp_sum32_r    <= '0;
            ipv4_sum32_r <= '0;
            odd_byte_r <= '0;
            byte_cnt_r <= '0;
            pkt_r <= '0;
        end else begin
            state      <= state_n;
            crc32_r    <= crc32_n;
            tcp_sum32_r <= tcp_sum32_n;
            odd_byte_r <= odd_byte_n;
            ipv4_sum32_r <= ipv4_sum32_n;
            byte_cnt_r <= byte_cnt_n;
            pkt_r <= pkt_n;
        end
    end

endmodule
