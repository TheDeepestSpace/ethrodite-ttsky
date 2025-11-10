`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"
`include "crc32.sv"

module ethernet_ipv4_handler #(
    parameter int DATA_WIDTH  = `INPUTWIDTH,
    parameter bit KEEP_ENABLE = 1
)(
    input  logic clk,
    input  logic rst_n,

    // AXI4-Stream slave
    axi_stream_if.slave s_axis,

    // AXI4-Stream master (forwarded payload)
    axi_stream_if.master m_axis,

    // Metadata outputs
    output logic       meta_valid,
    output logic       meta_crc32_valid,
    input logic        meta_ready,
    output logic [15:0] meta_pseudo_header,
    output logic [47:0] meta_dst_mac,
    output logic [47:0] meta_src_mac,
    output logic [31:0] meta_src_ip,
    output logic [31:0] meta_dst_ip,
    output logic [7:0]  meta_protocol,
    output logic [15:0] meta_total_length,
    output logic        meta_crc32_ok,
    output logic        meta_checksum_ok,
    output logic        meta_ethertype_ok,
    output logic        meta_length_ok
);

    localparam int BYTES = DATA_WIDTH/8;
    localparam int ETH_HEADER_BYTES = 14;

    typedef enum logic [1:0] {S_HEADER, S_FORWARD, S_CRC32, S_WAIT} state_e;
    state_e state_r, state_n;

    // Header registers
    logic [15:0] byte_offset_r, byte_offset_n;
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

    //larger in case of overflow
    logic [20:0] tcp_pseudo_r, tcp_pseudo_n;

    // Checksum
    logic [31:0] chksum_acc_r, chksum_acc_n;
    logic        odd_byte_valid_r, odd_byte_valid_n;
    logic [7:0]  odd_byte_r, odd_byte_n;
    logic [7:0]  header_bytes_needed_r, header_bytes_needed_n;
    logic [7:0]  header_bytes_accum_r, header_bytes_accum_n;
    logic [31:0] act_crc32_r, act_crc32_n, exp_crc_n, exp_crc_r;

    // Forwarded bytes counter
    logic [31:0] forwarded_bytes_r, forwarded_bytes_n;

    // Registered m_axis outputs to avoid mid-cycle glitches
    logic [BYTES-1:0] m_axis_tkeep_r, m_axis_tkeep_n;
    logic              m_axis_tlast_r, m_axis_tlast_n;
    logic [DATA_WIDTH-1:0] m_axis_tdata_r, m_axis_tdata_n;
    logic              m_axis_tvalid_r, m_axis_tvalid_n;

    // -----------------------------------------------------------------
    // AXI4 forwarding
    // m_axis.tdata mirrors incoming word. We must not assert tvalid when
    // the incoming beat contains no valid bytes (tkeep==0) because that
    // creates beats with tvalid=1 but no data. Use s_axis.tkeep to gate
    // tvalid when KEEP_ENABLE is active.
    assign m_axis.tdata  = m_axis_tdata_r;
    assign m_axis.tkeep  = m_axis_tkeep_r;
    assign m_axis.tlast  = m_axis_tlast_r;
    // assign m_axis.tkeep is driven in combinational logic below; defaults
    // are set inside the combinational block to avoid latches/glitches.
    assign m_axis.tuser  = '0;
    assign s_axis.tready = 1;
    // only assert valid when we're in forward state (registered state_r)
    // AND the incoming beat actually contains at least one valid byte
    // (or when KEEP_DISABLE). We'll register tvalid to keep it stable
    // during the cycle and avoid combinational hazards.
    assign m_axis.tvalid = m_axis_tvalid_r;

    function automatic int valid_bytes_in_beat(input logic [BYTES-1:0] tkeep);
        int cnt = 0;
        if (!KEEP_ENABLE) return BYTES;
        for (int i=0; i<BYTES; i++) if (tkeep[i]) cnt++;
        return cnt;
    endfunction

    function automatic logic [7:0] get_byte(input logic [DATA_WIDTH-1:0] word, input int bidx);
        return word[bidx*8+: 8];
    endfunction

    // -----------------------------------------------------------------
    // Combinational next-state
    always_comb begin
        // Defaults
        state_n = state_r;
        byte_offset_n = byte_offset_r;
        dst_mac_n = dst_mac_r; src_mac_n = src_mac_r;
        ethertype_n = ethertype_r; ethertype_ok_n = ethertype_ok_r;
        ipv4_version_n = ipv4_version_r; ipv4_ihl_n = ipv4_ihl_r;
        ipv4_total_length_n = ipv4_total_length_r;
        ipv4_protocol_n = ipv4_protocol_r;
        ipv4_src_ip_n = ipv4_src_ip_r; ipv4_dst_ip_n = ipv4_dst_ip_r;
        chksum_acc_n = chksum_acc_r; odd_byte_valid_n = odd_byte_valid_r; odd_byte_n = odd_byte_r;
        header_bytes_needed_n = header_bytes_needed_r; header_bytes_accum_n = header_bytes_accum_r;
        forwarded_bytes_n = forwarded_bytes_r; act_crc32_n = act_crc32_r; exp_crc_n = exp_crc_r;
        tcp_pseudo_n = tcp_pseudo_r;

    // Default next-state outputs to avoid combinational latches and
    // mid-cycle glitches. We compute next values here and register
    // them at the clock edge below so the external interface pins
    // are stable during the clock.
    m_axis_tkeep_n = '0;
    m_axis_tlast_n = 1'b0;
    // By default mirror the incoming data into the next registered
    // output so tdata is stable for the cycle when observed.
    m_axis_tdata_n = s_axis.tdata;
    // Default registered valid is deasserted; combinational logic will
    // set m_axis_tvalid_n when forwarding.
    m_axis_tvalid_n = 1'b0;

        if (s_axis.tvalid) begin
            automatic int valid_bytes = BYTES;
            //$display("[ETH_IPV4_HANDLER] Received AXI beat: state=%0d tdata=%0h tkeep=%0b tlast=%0b", state_r, s_axis.tdata, s_axis.tkeep, s_axis.tlast);
            if (KEEP_ENABLE) valid_bytes = valid_bytes_in_beat(s_axis.tkeep);

            for (int b=0; b<valid_bytes; b++) begin
                automatic logic [7:0] curbyte = get_byte(s_axis.tdata, b);
                automatic int pkt_offset = byte_offset_r + b;

                // Ethernet header
                case (pkt_offset)
                    (`ETH_DST_MAC_BASE + 0): dst_mac_n[47:40] = curbyte;
                    (`ETH_DST_MAC_BASE + 1): dst_mac_n[39:32] = curbyte;
                    (`ETH_DST_MAC_BASE + 2): dst_mac_n[31:24] = curbyte;
                    (`ETH_DST_MAC_BASE + 3): dst_mac_n[23:16] = curbyte;
                    (`ETH_DST_MAC_BASE + 4): dst_mac_n[15:8]  = curbyte;
                    (`ETH_DST_MAC_BASE + 5): dst_mac_n[7:0]   = curbyte;
                    (`ETH_SRC_MAC_BASE + 0): src_mac_n[47:40] = curbyte;
                    (`ETH_SRC_MAC_BASE + 1): src_mac_n[39:32] = curbyte;
                    (`ETH_SRC_MAC_BASE + 2): src_mac_n[31:24] = curbyte;
                    (`ETH_SRC_MAC_BASE + 3): src_mac_n[23:16] = curbyte;
                    (`ETH_SRC_MAC_BASE + 4): src_mac_n[15:8]  = curbyte;
                    (`ETH_SRC_MAC_BASE + 5): src_mac_n[7:0]   = curbyte;
                    (`ETH_TYPE_BASE + 0): ethertype_n[15:8] = curbyte;
                    (`ETH_TYPE_BASE + 1): begin
                        ethertype_n[7:0] = curbyte;
                        ethertype_ok_n = (ethertype_n == `ETH_TYPE_IPV4);
                    end
                endcase

                // IPv4 header
                if (pkt_offset >= ETH_HEADER_BYTES) begin
                    automatic int rel = pkt_offset - ETH_HEADER_BYTES;
                    case (rel)
                        `IPV4_VERSION_IHL_OFFSET: begin
                            ipv4_version_n = curbyte[7:4];
                            ipv4_ihl_n     = curbyte[3:0];
                            header_bytes_needed_n = ipv4_ihl_n * 4;
                            tcp_pseudo_n = tcp_pseudo_n-ipv4_ihl_n * 4;
                        end
                        `IPV4_TOTAL_LENGTH_MSB_OFFSET: 
                        begin
                            ipv4_total_length_n[15:8] = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + (curbyte<<8);
                        end
                        `IPV4_TOTAL_LENGTH_LSB_OFFSET: 
                        begin
                            ipv4_total_length_n[7:0]  = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + curbyte;
                        end
                        `IPV4_PROTOCOL_OFFSET: ipv4_protocol_n = curbyte;
                        (`IPV4_SRC_IP_OFFSET + 0): begin
                            ipv4_src_ip_n[31:24] = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + (curbyte<<8);
                        end
                        (`IPV4_SRC_IP_OFFSET + 1): begin
                            ipv4_src_ip_n[23:16] = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + curbyte;
                        end
                        (`IPV4_SRC_IP_OFFSET + 2): begin
                            ipv4_src_ip_n[15:8] = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + (curbyte<<8);
                        end
                        (`IPV4_SRC_IP_OFFSET + 3): begin
                            ipv4_src_ip_n[7:0] = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + curbyte;
                        end

                        // -------- IPv4 destination IP --------
                        (`IPV4_DST_IP_OFFSET + 0): begin
                            ipv4_dst_ip_n[31:24] = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + (curbyte<<8);
                        end
                        (`IPV4_DST_IP_OFFSET + 1): begin
                            ipv4_dst_ip_n[23:16] = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + curbyte;
                        end
                        (`IPV4_DST_IP_OFFSET + 2): begin
                            ipv4_dst_ip_n[15:8] = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + (curbyte<<8);
                        end
                        (`IPV4_DST_IP_OFFSET + 3): begin
                            ipv4_dst_ip_n[7:0] = curbyte;
                            tcp_pseudo_n = tcp_pseudo_n + curbyte;
                        end

                    endcase

                    // Checksum streaming
                    if (header_bytes_accum_n < header_bytes_needed_n) begin
                        if (!odd_byte_valid_n) begin
                            odd_byte_n = curbyte;
                            odd_byte_valid_n = 1'b1;
                        end else begin
                            chksum_acc_n = chksum_acc_n + {odd_byte_n, curbyte};
                            chksum_acc_n = (chksum_acc_n & 16'hFFFF) + (chksum_acc_n >> 16);
                            odd_byte_valid_n = 0;
                        end
                    end
                    if (header_bytes_accum_n < ipv4_total_length_r || forwarded_bytes_n == 0)
                        exp_crc_n = crc(exp_crc_n, curbyte);
                    header_bytes_accum_n = header_bytes_accum_n + 1;
                end
            end
            byte_offset_n = byte_offset_r + valid_bytes;

            // State transitions
            case (state_r)
                S_HEADER: begin
                    if (header_bytes_accum_n >= header_bytes_needed_n && header_bytes_needed_n != 0) begin
                        // Compute leftover bytes from header accumulation
                        automatic int first_forward_bytes = header_bytes_accum_n - header_bytes_needed_n;
                        forwarded_bytes_n = forwarded_bytes_r + first_forward_bytes;

                        // Move to forward state
                        state_n = S_FORWARD;

                        // Set tkeep for first beat
                        if (first_forward_bytes == 0)
                        begin
                            m_axis_tkeep_n = '0;
                        end
                        else if (first_forward_bytes > 0) begin
                            //m_axis_tkeep_n = (1 << first_forward_bytes) - 1;
                            m_axis_tdata_n = (m_axis_tdata_n >> ((BYTES - first_forward_bytes)*8)); // upper N bits
                            m_axis_tkeep_n = ({BYTES{1'b1}} >> (BYTES - first_forward_bytes)); // upper N bits
                            m_axis_tvalid_n = 1'b1;
                        end
                        else begin
                            m_axis_tvalid_n = 1'b1;
                            m_axis_tkeep_n = {BYTES{1'b1}}; // full beat
                        end
                    end
                end

                S_FORWARD: begin
                    // Remaining bytes in payload
                    automatic int remaining_bytes = (ipv4_total_length_r - ipv4_ihl_r*4) - forwarded_bytes_r;

                    // Increment forwarded bytes   
                    forwarded_bytes_n = forwarded_bytes_r + valid_bytes;

                    // Default tkeep = all bytes valid
                    m_axis_tkeep_n = {BYTES{1'b1}};

                    // Set next-cycle tvalid when forwarding bytes
                    m_axis_tvalid_n =  (KEEP_ENABLE ? |s_axis.tkeep : 1'b1);

                    // Last beat: only remaining_bytes are valid
                    if (remaining_bytes < BYTES) begin
                        m_axis_tkeep_n = ({BYTES{1'b1}} >> (BYTES - remaining_bytes)); // upper N bits
                        //m_axis_tdata_n = (m_axis_tdata_n >> ((BYTES - remaining_bytes)*8)); // upper N bits
                    end
                    
                    // Done forwarding?
                    if (forwarded_bytes_n >= ipv4_total_length_r - ipv4_ihl_r*4) begin
                        m_axis_tlast_n = 1;
                        for (int i = remaining_bytes; i<valid_bytes; i++)
                        begin
                            automatic logic [7:0] curbyte = get_byte(s_axis.tdata, i);
                            act_crc32_n = act_crc32_n<<8  | curbyte;
                        end
                        state_n = (valid_bytes -remaining_bytes == `CRC32_WIDTH)? S_WAIT:S_CRC32;
                    end
                    else begin
                        m_axis_tlast_n = 0;
                    end
                end
            S_CRC32:begin                    
                    // Increment forwarded bytes
                    forwarded_bytes_n = forwarded_bytes_r + valid_bytes;

                    // Done forwarding?
                    for (int i = 0; i<valid_bytes; i++)
                    begin
                        automatic logic [7:0] curbyte = get_byte(s_axis.tdata, i);
                        act_crc32_n = act_crc32_n<<8  | curbyte;
                    end
                    state_n = (forwarded_bytes_n -(ipv4_total_length_r - ipv4_ihl_r*4) == `CRC32_WIDTH)? S_WAIT:S_CRC32;
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
            chksum_acc_r        <= 0; odd_byte_valid_r <= 0; odd_byte_r <= 0;
            header_bytes_needed_r <= 0; header_bytes_accum_r <= 0;
            forwarded_bytes_r   <= 0; act_crc32_r <= 0;
            tcp_pseudo_r <= `IPV4_TCP_PROTO;
            

            meta_valid          <= 0; meta_crc32_valid <= 0;
            meta_dst_mac        <= 0; meta_src_mac <= 0;
            meta_src_ip         <= 0; meta_dst_ip <= 0;
            meta_protocol       <= 0; meta_total_length <= 0;
            meta_checksum_ok    <= 0; meta_ethertype_ok <= 0; meta_length_ok <= 0;
            exp_crc_r <= 32'hFFFFFFFF;
            // clear registered outputs
            m_axis_tkeep_r <= '0; m_axis_tlast_r <= 1'b0; m_axis_tdata_r <= '0;
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
            act_crc32_r             <= act_crc32_n;
            exp_crc_r <= exp_crc_n; tcp_pseudo_r <= tcp_pseudo_n;

            // latch interface outputs
            m_axis_tkeep_r <= m_axis_tkeep_n;
            m_axis_tlast_r <= m_axis_tlast_n;
            m_axis_tdata_r <= m_axis_tdata_n;
            m_axis_tvalid_r <= m_axis_tvalid_n;

            // ---------------------------
            // Metadata latching
            // Once header is complete, latch metadata from _n and keep valid high during forwarding
            if (state_n == S_FORWARD) begin
                logic [15:0] sum16_ipv4, sum16_tcp;

                meta_valid          <= 1;
                meta_dst_mac        <= dst_mac_n;
                meta_src_mac        <= src_mac_n;
                meta_src_ip         <= ipv4_src_ip_n;
                meta_dst_ip         <= ipv4_dst_ip_n;
                meta_protocol       <= ipv4_protocol_n;
                meta_total_length   <= ipv4_total_length_n;

                // checksum calculation
                sum16_ipv4 = chksum_acc_n[15:0] + (chksum_acc_n >> 16);
                sum16_ipv4 = sum16_ipv4[15:0] + (sum16_ipv4 >> 16);
                meta_checksum_ok    <= (sum16_ipv4 == 16'hFFFF);
                meta_ethertype_ok   <= ethertype_ok_n;
                meta_length_ok      <= (ipv4_total_length_n >= ipv4_ihl_n*4);

                //folding the tcp pseudo header checksum so it can be continued by the tcp header
                sum16_tcp = tcp_pseudo_n[15:0] + (tcp_pseudo_n >> 16); // add upper bits
                sum16_tcp = sum16_tcp[15:0] + (sum16_tcp >> 16);                       // handle carry from first addition
                meta_pseudo_header <= sum16_tcp;
            end
            else if (state_n == S_WAIT)
            begin
                meta_crc32_valid <= 1;
                meta_crc32_ok <= (act_crc32_n==exp_crc_n);
                //$display("[ETH_IPV4_HANDLER] Latching metadata: dst_mac=%0h src_mac=%0h src_ip=%0h dst_ip=%0h protocol=%0d total_length=%0d",
                //         meta_dst_mac, meta_src_mac, meta_src_ip, meta_dst_ip, meta_protocol, meta_total_length);
            end
        end
    end

endmodule
