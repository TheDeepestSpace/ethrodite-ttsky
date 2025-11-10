`timescale 1ns/1ps
`include "ethernet_info.svh"

module ethernet_ipv4_handler #(
    parameter int DATA_WIDTH  = `INPUTWIDTH
)(
    input  logic clk,
    input  logic rst_n,

    // AXI4-Stream slave
    input  logic [DATA_WIDTH-1:0] s_axis_tdata,
    input  logic                  s_axis_tvalid,
    output logic                  s_axis_tready,
    input  logic                  s_axis_tlast,

    // AXI4-Stream master (forwarded payload)
    output logic [DATA_WIDTH-1:0] m_axis_tdata,
    output logic                  m_axis_tvalid,
    input  logic                  m_axis_tready,
    output logic                  m_axis_tlast,

    // Metadata outputs
    output logic       meta_valid,
    input logic        meta_ready,
    output logic [47:0] meta_dst_mac,
    output logic [47:0] meta_src_mac,
    output logic [31:0] meta_src_ip,
    output logic [31:0] meta_dst_ip,
    output logic [7:0]  meta_protocol,
    output logic [15:0] meta_total_length,
    output logic        meta_ethertype_ok
);

    localparam [15:0] ETH_HEADER_BYTES = 14;

    localparam S_HEADER  = 4'd0;
    localparam S_FORWARD = 4'd1;
    localparam S_CRC32   = 4'd2;
    localparam S_WAIT    = 4'd3;
    localparam S_DROP    = 4'd4;
    logic [3:0] state_r, state_n;

    // Header registers
    logic [15:0] byte_offset_r, byte_offset_n;
    logic [15:0] rel;  // temporary variable for relative offset
    logic [16:0] sum16_ipv4;  // 17-bit to handle carries in checksum calculation
    logic [47:0] dst_mac_r, dst_mac_n;
    logic [47:0] src_mac_r, src_mac_n;
    logic [15:0] ethertype_r, ethertype_n;
    logic        ethertype_ok_r, ethertype_ok_n;

    logic [3:0]  ipv4_version_r, ipv4_version_n;
    logic [3:0]  ipv4_ihl_r, ipv4_ihl_n;
    logic [15:0] ipv4_total_length_r, ipv4_total_length_n;
    logic [7:0]  ipv4_protocol_r, ipv4_protocol_n;
    logic [31:0] ipv4_src_ip_r, ipv4_src_ip_n;
    logic [31:0] ipv4_dst_ip_r, ipv4_dst_ip_n;

    // Checksum
    logic [31:0] chksum_acc_r, chksum_acc_n;
    logic        odd_byte_valid_r, odd_byte_valid_n;
    logic [7:0]  odd_byte_r, odd_byte_n;
    logic [7:0]  header_bytes_needed_r, header_bytes_needed_n;
    logic [7:0]  header_bytes_accum_r, header_bytes_accum_n;

    // Forwarded bytes counter
    logic [31:0] forwarded_bytes_r, forwarded_bytes_n;

    // Registered m_axis outputs to avoid mid-cycle glitches
    logic              m_axis_tlast_r, m_axis_tlast_n;
    logic [DATA_WIDTH-1:0] m_axis_tdata_r, m_axis_tdata_n;
    logic              m_axis_tvalid_r, m_axis_tvalid_n;

    // -----------------------------------------------------------------
    // AXI4 forwarding
    assign m_axis_tdata  = m_axis_tdata_r;
    assign m_axis_tlast  = m_axis_tlast_r;
    // are set inside the combinational block to avoid latches/glitches.
    assign s_axis_tready = state_r != S_WAIT;
    assign m_axis_tvalid = m_axis_tvalid_r;

    // -----------------------------------------------------------------
    // Combinational next-state
    always_comb begin
        // Defaults
        state_n = state_r;
        byte_offset_n = byte_offset_r;
        rel = '0;  // Default to avoid latch inference
        dst_mac_n = dst_mac_r; src_mac_n = src_mac_r;
        ethertype_n = ethertype_r; ethertype_ok_n = ethertype_ok_r;
        ipv4_version_n = ipv4_version_r; ipv4_ihl_n = ipv4_ihl_r;
        ipv4_total_length_n = ipv4_total_length_r;
        ipv4_protocol_n = ipv4_protocol_r;
        ipv4_src_ip_n = ipv4_src_ip_r; ipv4_dst_ip_n = ipv4_dst_ip_r;
        chksum_acc_n = chksum_acc_r; odd_byte_valid_n = odd_byte_valid_r; odd_byte_n = odd_byte_r;
        header_bytes_needed_n = header_bytes_needed_r; header_bytes_accum_n = header_bytes_accum_r;
        forwarded_bytes_n = forwarded_bytes_r;

    // Default next-state outputs to avoid combinational latches and
    // mid-cycle glitches. We compute next values here and register
    // them at the clock edge below so the external interface pins
    // are stable during the clock.
    m_axis_tlast_n = 1'b0;
    // By default mirror the incoming data into the next registered
    // output so tdata is stable for the cycle when observed.
    m_axis_tdata_n = s_axis_tdata;
    // Default registered valid is deasserted; combinational logic will
    // set m_axis_tvalid_n when forwarding.
    m_axis_tvalid_n = 1'b0;

    if (s_axis_tvalid) begin
        // Ethernet header
        case (byte_offset_r)
            (`ETH_DST_MAC_BASE + 0): dst_mac_n[47:40] = s_axis_tdata;
            (`ETH_DST_MAC_BASE + 1): dst_mac_n[39:32] = s_axis_tdata;
            (`ETH_DST_MAC_BASE + 2): dst_mac_n[31:24] = s_axis_tdata;
            (`ETH_DST_MAC_BASE + 3): dst_mac_n[23:16] = s_axis_tdata;
            (`ETH_DST_MAC_BASE + 4): dst_mac_n[15:8]  = s_axis_tdata;
            (`ETH_DST_MAC_BASE + 5): dst_mac_n[7:0]   = s_axis_tdata;
            (`ETH_SRC_MAC_BASE + 0): src_mac_n[47:40] = s_axis_tdata;
            (`ETH_SRC_MAC_BASE + 1): src_mac_n[39:32] = s_axis_tdata;
            (`ETH_SRC_MAC_BASE + 2): src_mac_n[31:24] = s_axis_tdata;
            (`ETH_SRC_MAC_BASE + 3): src_mac_n[23:16] = s_axis_tdata;
            (`ETH_SRC_MAC_BASE + 4): src_mac_n[15:8]  = s_axis_tdata;
            (`ETH_SRC_MAC_BASE + 5): src_mac_n[7:0]   = s_axis_tdata;
            (`ETH_TYPE_BASE + 0): ethertype_n[15:8] = s_axis_tdata;
            (`ETH_TYPE_BASE + 1): begin
                ethertype_n[7:0] = s_axis_tdata;
                ethertype_ok_n = (ethertype_n == `ETH_TYPE_IPV4);
            end
            default: ;
        endcase

        // IPv4 header
        if (byte_offset_r >= ETH_HEADER_BYTES) begin
            rel = byte_offset_r - ETH_HEADER_BYTES;
            case (rel)
                `IPV4_VERSION_IHL_OFFSET: begin
                    ipv4_version_n = s_axis_tdata[7:4];
                    ipv4_ihl_n     = s_axis_tdata[3:0];
                    header_bytes_needed_n = ipv4_ihl_n * 4;
                end
                `IPV4_TOTAL_LENGTH_MSB_OFFSET:
                begin
                    ipv4_total_length_n[15:8] = s_axis_tdata;
                end
                `IPV4_TOTAL_LENGTH_LSB_OFFSET:
                begin
                    ipv4_total_length_n[7:0]  = s_axis_tdata;
                end
                `IPV4_PROTOCOL_OFFSET: ipv4_protocol_n = s_axis_tdata;
                (`IPV4_SRC_IP_OFFSET + 0): begin
                    ipv4_src_ip_n[31:24] = s_axis_tdata;
                end
                (`IPV4_SRC_IP_OFFSET + 1): begin
                    ipv4_src_ip_n[23:16] = s_axis_tdata;
                end
                (`IPV4_SRC_IP_OFFSET + 2): begin
                    ipv4_src_ip_n[15:8] = s_axis_tdata;
                end
                (`IPV4_SRC_IP_OFFSET + 3): begin
                    ipv4_src_ip_n[7:0] = s_axis_tdata;
                end

                // -------- IPv4 destination IP --------
                (`IPV4_DST_IP_OFFSET + 0): begin
                    ipv4_dst_ip_n[31:24] = s_axis_tdata;
                end
                (`IPV4_DST_IP_OFFSET + 1): begin
                    ipv4_dst_ip_n[23:16] = s_axis_tdata;
                end
                (`IPV4_DST_IP_OFFSET + 2): begin
                    ipv4_dst_ip_n[15:8] = s_axis_tdata;
                end
                (`IPV4_DST_IP_OFFSET + 3): begin
                    ipv4_dst_ip_n[7:0] = s_axis_tdata;
                end
            endcase

            if (!odd_byte_valid_n) begin
                odd_byte_n = s_axis_tdata;
                odd_byte_valid_n = 1'b1;
            end else begin
                chksum_acc_n = chksum_acc_n + 16'({odd_byte_n, s_axis_tdata});
                //chksum_acc_n = chksum_acc_n + 16'( {odd_byte_n, s_axis.tdata} );
                //chksum_acc_n = (chksum_acc_n & 16'hFFFF) + (chksum_acc_n >> 16);
                odd_byte_valid_n = 0;
            end

            header_bytes_accum_n = header_bytes_accum_n + 1;
        end
        else begin
            odd_byte_valid_n = 0;
        end
        byte_offset_n = byte_offset_r + 1;

        // State transitions
        case (state_r)
            S_HEADER: begin
                if (header_bytes_accum_n == header_bytes_needed_n && header_bytes_needed_n != 0) begin
                    sum16_ipv4 = chksum_acc_n[15:0] + chksum_acc_n[31:16];
                    sum16_ipv4 = sum16_ipv4[15:0] + {16'b0, sum16_ipv4[16]};

                    // Valid checksum if ones-complement sum == 0xFFFF
                    if (sum16_ipv4[15:0] == 16'hFFFF)
                        state_n = S_FORWARD;
                    else
                        state_n = S_DROP;
                end
            end

            S_FORWARD: begin
                // Increment forwarded bytes
                forwarded_bytes_n = forwarded_bytes_r + 1;

                // Set next-cycle tvalid when forwarding bytes
                m_axis_tvalid_n =  s_axis_tvalid;
                // Done forwarding?
                if (forwarded_bytes_n == ipv4_total_length_r - {12'b0, ipv4_ihl_r}*4 ) begin
                    m_axis_tlast_n = 1;
                    state_n = S_CRC32;
                end
                else begin
                    m_axis_tlast_n = 0;
                end
            end
            S_DROP: begin
                // Increment forwarded bytes
                forwarded_bytes_n = forwarded_bytes_r + 1;

                // Done forwarding?
                if (forwarded_bytes_n == ipv4_total_length_r - {12'b0, ipv4_ihl_r}*4 +4) begin
                    state_n = S_HEADER;
                end
            end
        S_CRC32:begin
                // Increment forwarded bytes
                forwarded_bytes_n = forwarded_bytes_r + 1;

                if (forwarded_bytes_n -(ipv4_total_length_r - {12'b0, ipv4_ihl_r}*4) == `CRC32_WIDTH) begin
                    state_n = S_WAIT;
                end
                else
                    state_n = S_CRC32;
        end
        endcase
    end
    end

    // -----------------------------------------------------------------
    // Sequential updates
    always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n || (state_r == S_WAIT && meta_ready)) begin
            // Reset all state and metadata
            state_r             <= S_HEADER;
            byte_offset_r       <= 0;
            dst_mac_r           <= 0; src_mac_r <= 0;
            ethertype_r         <= 0; ethertype_ok_r <= 0;
            ipv4_version_r      <= 0; ipv4_ihl_r <= 0;
            ipv4_total_length_r <= 0; ipv4_protocol_r <= 0;
            ipv4_src_ip_r       <= 0; ipv4_dst_ip_r <= 0;
            odd_byte_valid_r <= 0; odd_byte_r <= 0;
            header_bytes_needed_r <= 0; header_bytes_accum_r <= 0;
            forwarded_bytes_r   <= 0;

            chksum_acc_r <= '0;

            meta_valid          <= 0;
            meta_dst_mac        <= 0; meta_src_mac <= 0;
            meta_src_ip         <= 0; meta_dst_ip <= 0;
            meta_protocol       <= 0; meta_total_length <= 0;
            meta_ethertype_ok <= 0;

            // clear registered outputs
            m_axis_tlast_r <= 1'b0; m_axis_tdata_r <= '0;
        end
        else begin
            // Latch state
            state_r             <= state_n;
            byte_offset_r       <= byte_offset_n;
            dst_mac_r           <= dst_mac_n; src_mac_r <= src_mac_n;
            ethertype_r         <= ethertype_n; ethertype_ok_r <= ethertype_ok_n;
            ipv4_version_r      <= ipv4_version_n; ipv4_ihl_r <= ipv4_ihl_n;
            ipv4_total_length_r <= ipv4_total_length_n; ipv4_protocol_r <= ipv4_protocol_n;
            ipv4_src_ip_r       <= ipv4_src_ip_n; ipv4_dst_ip_r <= ipv4_dst_ip_n;
            chksum_acc_r        <= chksum_acc_n; odd_byte_valid_r <= odd_byte_valid_n; odd_byte_r <= odd_byte_n;
            header_bytes_needed_r <= header_bytes_needed_n; header_bytes_accum_r <= header_bytes_accum_n;
            forwarded_bytes_r   <= forwarded_bytes_n;

            meta_valid          <= (state_n == S_WAIT);

            // latch interface outputs
            m_axis_tlast_r <= m_axis_tlast_n;
            m_axis_tdata_r <= m_axis_tdata_n;
            m_axis_tvalid_r <= m_axis_tvalid_n;

            // ---------------------------
            // Metadata latching
            // Once header is complete, latch metadata from _n and keep valid high during forwarding
            if (state_n == S_FORWARD) begin
                meta_dst_mac        <= dst_mac_n;
                meta_src_mac        <= src_mac_n;
                meta_src_ip         <= ipv4_src_ip_n;
                meta_dst_ip         <= ipv4_dst_ip_n;
                meta_protocol       <= ipv4_protocol_n;
                meta_total_length   <= ipv4_total_length_n;
            end
        end
    end

endmodule
