// tcp_send.sv
`timescale 1ns/1ps
`include "ethernet_info.svh"
`include "crc32.sv"
`include "axi_stream_if.sv"

// TCP Packet Info Struct
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
    logic [7:0]  tcp_flags;    // bits per ethernet_info.svh
    logic [15:0] window;
    logic [15:0] payload_len;  // bytes
    logic [15:0] tcp_checksum; // precomputed externally if payload present
} tcp_packet_info_s;
`endif // TCP_PACKET_INFO_S_SV

module tcp_sender #(
    parameter int DATA_WIDTH = `INPUTWIDTH // default 64
) (
    input  logic                    clk,
    input  logic                    rst_n,

    // control / instruction (sampled on start)
    input  logic                    start,          // pulse to begin
    input  tcp_packet_info_s        i_pkt,

    // payload AXI-Stream slave (optional) -- passthrough to m_axis after headers
    axi_stream_if.slave             s_axis,

    // frame AXI-Stream master output
    axi_stream_if.master            m_axis,

    // status
    output logic                    busy
);

    // derived
    localparam int AXI_BYTES_PER_BEAT = `AXI_BYTES(DATA_WIDTH);
    localparam int HEADER_BYTES = `ETH_HEADER_BYTES + `IPV4_HEADER_BYTES + `TCP_HEADER_MIN_LEN;

    // internal header buffer (we need to patch IPv4 checksum and insert tcp checksum)
    logic [7:0] header_buf [0:HEADER_BYTES-1];
    logic [7:0] header_buf_prev[0:HEADER_BYTES-1];

    // latched instruction fields
    logic [47:0] src_mac, dst_mac;
    logic [31:0] src_ip, dst_ip;
    logic [15:0] src_port, dst_port;
    logic [31:0] seq_num, ack_num;
    logic [15:0] window;
    logic [7:0]  tcp_flags;
    logic        has_payload;
    logic [15:0] payload_len, prev_payload_len;
    logic [15:0] payload_checksum, payload_checksum_prev;
    logic [31:0] tcp_checksum, ipv4_checksum, pseudo_checksum, final_tcp;
    logic tcp_checksum_valid, tcp_checksum_valid_n, ipv4_checksum_valid, ipv4_checksum_valid_n, pseudo_checksum_valid, pseudo_checksum_valid_n;

    // frame / send bookkeeping
    int total_frame_bytes; // header + payload_len
    int beats_total;

    logic [31:0] send_byte_idx_r, send_byte_idx_n;
    logic [31:0] crc32_n, crc32_r;

    // FSM
    typedef enum logic [2:0] {
        ST_IDLE,
        ST_CHECKSUM,
        ST_SEND_HDRS,
        ST_FORWARD_PAYLOAD,
        ST_CRC32
    } state_e;
    state_e state, state_n;

    // outputs default
    assign busy = (state != ST_IDLE);

    // s_axis.tready default
    assign s_axis.tready = (state == ST_FORWARD_PAYLOAD) && m_axis.tready; // only accept when we can forward

    // helper: finalize 32-bit sum into 16-bit one's complement
    function automatic logic [15:0] finalize_csum(input logic [31:0] sum32);
        logic [31:0] s;
        begin
            s = sum32;
            // fold carries
            while (s >> 16)
                s = (s & 32'hFFFF) + (s >> 16);
            finalize_csum = ~s[15:0];
        end
    endfunction

    // Build header into header_buf using latched fields
    task automatic build_header();
        int ip_base = `ETH_HEADER_BYTES;
        int tcp_base = `ETH_HEADER_BYTES + `IPV4_HEADER_BYTES;
        int total_ip_len;
        int ip_c = finalize_csum(ipv4_checksum);
        int tcp_c = finalize_csum(final_tcp);
        begin
            // Ethernet
            header_buf[`ETH_DST_MAC_0] = dst_mac[47:40];
            header_buf[`ETH_DST_MAC_1] = dst_mac[39:32];
            header_buf[`ETH_DST_MAC_2] = dst_mac[31:24];
            header_buf[`ETH_DST_MAC_3] = dst_mac[23:16];
            header_buf[`ETH_DST_MAC_4] = dst_mac[15:8];
            header_buf[`ETH_DST_MAC_5] = dst_mac[7:0];

            header_buf[`ETH_SRC_MAC_0] = src_mac[47:40];
            header_buf[`ETH_SRC_MAC_1] = src_mac[39:32];
            header_buf[`ETH_SRC_MAC_2] = src_mac[31:24];
            header_buf[`ETH_SRC_MAC_3] = src_mac[23:16];
            header_buf[`ETH_SRC_MAC_4] = src_mac[15:8];
            header_buf[`ETH_SRC_MAC_5] = src_mac[7:0];

            header_buf[`ETH_TYPE_MSB_OFFSET] = 8'h08;
            header_buf[`ETH_TYPE_LSB_OFFSET] = 8'h00;

            // IPv4 header (IHL=5, no options)
            total_ip_len = `IPV4_HEADER_BYTES + `TCP_HEADER_MIN_LEN + payload_len;
            header_buf[ip_base + `IPV4_VERSION_IHL_OFFSET] = 8'h45;
            header_buf[ip_base + `IPV4_DSCP_ECN_OFFSET] = 8'h00;
            header_buf[ip_base + `IPV4_TOTAL_LENGTH_MSB_OFFSET] = total_ip_len[15:8];
            header_buf[ip_base + `IPV4_TOTAL_LENGTH_LSB_OFFSET] = total_ip_len[7:0];
            header_buf[ip_base + `IPV4_IDENT_MSB_OFFSET] = 8'h00;
            header_buf[ip_base + `IPV4_IDENT_LSB_OFFSET] = 8'h00;
            header_buf[ip_base + `IPV4_FLAGS_FRAG_MSB_OFFSET] = 8'h40; // DF
            header_buf[ip_base + `IPV4_FLAGS_FRAG_LSB_OFFSET] = 8'h00;
            header_buf[ip_base + `IPV4_TTL_OFFSET] = 8'h40;
            header_buf[ip_base + `IPV4_PROTOCOL_OFFSET] = `IPV4_PROTOCOL_TCP;
            header_buf[ip_base + `IPV4_CHECKSUM_MSB_OFFSET] = ip_c[15:8]; // to be filled
            header_buf[ip_base + `IPV4_CHECKSUM_LSB_OFFSET] = ip_c[7:0];

            // src/dst IP
            header_buf[ip_base + `IPV4_SRC_IP_OFFSET + 0] = src_ip[31:24];
            header_buf[ip_base + `IPV4_SRC_IP_OFFSET + 1] = src_ip[23:16];
            header_buf[ip_base + `IPV4_SRC_IP_OFFSET + 2] = src_ip[15:8];
            header_buf[ip_base + `IPV4_SRC_IP_OFFSET + 3] = src_ip[7:0];

            header_buf[ip_base + `IPV4_DST_IP_OFFSET + 0] = dst_ip[31:24];
            header_buf[ip_base + `IPV4_DST_IP_OFFSET + 1] = dst_ip[23:16];
            header_buf[ip_base + `IPV4_DST_IP_OFFSET + 2] = dst_ip[15:8];
            header_buf[ip_base + `IPV4_DST_IP_OFFSET + 3] = dst_ip[7:0];

            // TCP header (no options)
            header_buf[tcp_base + `TCP_SRC_PORT_BASE + 0] = src_port[15:8];
            header_buf[tcp_base + `TCP_SRC_PORT_BASE + 1] = src_port[7:0];
            header_buf[tcp_base + `TCP_DST_PORT_BASE + 0] = dst_port[15:8];
            header_buf[tcp_base + `TCP_DST_PORT_BASE + 1] = dst_port[7:0];

            header_buf[tcp_base + `TCP_SEQ_NUM_BASE + 0] = seq_num[31:24];
            header_buf[tcp_base + `TCP_SEQ_NUM_BASE + 1] = seq_num[23:16];
            header_buf[tcp_base + `TCP_SEQ_NUM_BASE + 2] = seq_num[15:8];
            header_buf[tcp_base + `TCP_SEQ_NUM_BASE + 3] = seq_num[7:0];

            header_buf[tcp_base + `TCP_ACK_NUM_BASE + 0] = ack_num[31:24];
            header_buf[tcp_base + `TCP_ACK_NUM_BASE + 1] = ack_num[23:16];
            header_buf[tcp_base + `TCP_ACK_NUM_BASE + 2] = ack_num[15:8];
            header_buf[tcp_base + `TCP_ACK_NUM_BASE + 3] = ack_num[7:0];

            header_buf[tcp_base + `TCP_DATA_OFFSET_BASE] = 8'h50; // data offset=5 (20 bytes)
            header_buf[tcp_base + `TCP_FLAGS_BASE] = tcp_flags;
            header_buf[tcp_base + `TCP_WINDOW_SIZE_BASE + 0] = window[15:8];
            header_buf[tcp_base + `TCP_WINDOW_SIZE_BASE + 1] = window[7:0];
            header_buf[tcp_base + `TCP_CHECKSUM_BASE + 0] = tcp_c[15:8];
            header_buf[tcp_base + `TCP_CHECKSUM_BASE + 1] = tcp_c[7:0];

            header_buf[tcp_base + `TCP_URGENT_PTR_BASE + 0] = 8'h00;
            header_buf[tcp_base + `TCP_URGENT_PTR_BASE + 1] = 8'h00;
        end
    endtask

    // -----------------------------
    // FSM sequential
    // -----------------------------
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= ST_IDLE;
            payload_checksum_prev <= '0;
            prev_payload_len <= '0;
            tcp_checksum <='0;
            ipv4_checksum<='0;
            pseudo_checksum <= (`IPV4_TCP_PROTO<<8)+(`TCP_HEADER_MIN_LEN);  // 0x0600
            tcp_checksum_valid<=0;
            ipv4_checksum_valid<=0;
            pseudo_checksum_valid <= 0;
            for (int i=0; i<HEADER_BYTES; i++)
                header_buf_prev[i] <= '0;
            // clear outputs
        end else begin
            send_byte_idx_r <= send_byte_idx_n;
            state <= state_n;

            if (state == ST_IDLE)
            begin
                // latch instruction fields synchronously (we already used non-blocking in seq block).
                // but since this block is combinational, copy inputs into latched regs here before build step:
                src_mac         <= i_pkt.src_mac;
                dst_mac         <= i_pkt.dst_mac;
                src_ip          <= i_pkt.src_ip;
                dst_ip          <= i_pkt.dst_ip;
                src_port        <= i_pkt.src_port;
                dst_port        <= i_pkt.dst_port;
                seq_num         <= i_pkt.seq_num;
                ack_num         <= i_pkt.ack_num;
                tcp_flags       <= i_pkt.tcp_flags;
                window          <= i_pkt.window;

                has_payload     <= (i_pkt.payload_len != 0);
                payload_len     <= i_pkt.payload_len;
                payload_checksum<= i_pkt.tcp_checksum;
                crc32_r <= 32'hFFFFFFFF;
                tcp_checksum_valid <= 0;
                ipv4_checksum_valid<=0;
                // Build header now that we've latched the instruction fields
                // into the synchronous registers. Doing this in the
                // sequential domain prevents 'x' propagation when the
                // inputs were not yet stable in combinational evaluation.
                build_header();
            end
            else if (state == ST_CHECKSUM)
            begin
                ipv4_checksum_valid_n = 1;
                tcp_checksum_valid_n = 1;
                pseudo_checksum_valid_n = 1;

                for (int byte_off = 0; byte_off < `IPV4_HEADER_BYTES; byte_off += 2) begin
                    if (byte_off == `IPV4_CHECKSUM_MSB_OFFSET || !ipv4_checksum_valid_n) begin
                        // Skip checksum field
                    end
                    else begin
                        automatic logic [7:0] ip_byte0 = header_buf[`ETH_HEADER_BYTES + byte_off];
                        automatic logic [7:0] ip_byte1 = header_buf[`ETH_HEADER_BYTES + byte_off + 1];

                        if (ip_byte0 != header_buf_prev[`ETH_HEADER_BYTES + byte_off] ||
                            ip_byte1 != header_buf_prev[`ETH_HEADER_BYTES + byte_off + 1]) begin

                            automatic logic [15:0] old_word = {header_buf_prev[`ETH_HEADER_BYTES + byte_off],
                                        header_buf_prev[`ETH_HEADER_BYTES + byte_off + 1]};
                            automatic logic [15:0] new_word = {ip_byte0, ip_byte1};

                            ipv4_checksum <= ipv4_checksum - old_word + new_word;

                            header_buf_prev[`ETH_HEADER_BYTES + byte_off]     <= ip_byte0;
                            header_buf_prev[`ETH_HEADER_BYTES + byte_off + 1] <= ip_byte1;
                            ipv4_checksum_valid_n = 0;
                            pseudo_checksum_valid_n = 0;
                            
                            // TCP pseudo-header: only source and destination IP
                            if (byte_off >= `IPV4_SRC_IP_OFFSET && byte_off < `IPV4_SRC_IP_OFFSET+4 ||
                                byte_off >= `IPV4_DST_IP_OFFSET && byte_off < `IPV4_DST_IP_OFFSET+4)
                            begin
                                pseudo_checksum <= pseudo_checksum - old_word + new_word;
                            end
                        end
                    end
                end
                for (int byte_off = 0; byte_off < `TCP_HEADER_MIN_LEN; byte_off += 2) begin
                    if (byte_off == `TCP_CHECKSUM_BASE || !tcp_checksum_valid_n) begin
                        // Skip checksum word
                    end
                    else begin
                        automatic logic [7:0] tcp_byte0 = header_buf[`ETH_HEADER_BYTES + `IPV4_HEADER_BYTES + byte_off];
                        automatic logic [7:0] tcp_byte1 = header_buf[`ETH_HEADER_BYTES + `IPV4_HEADER_BYTES + byte_off + 1];

                        if (tcp_byte0 != header_buf_prev[`ETH_HEADER_BYTES + `IPV4_HEADER_BYTES + byte_off] ||
                            tcp_byte1 != header_buf_prev[`ETH_HEADER_BYTES + `IPV4_HEADER_BYTES + byte_off + 1]) begin

                            automatic logic [15:0] old_word = {header_buf_prev[`ETH_HEADER_BYTES + `IPV4_HEADER_BYTES + byte_off],
                                        header_buf_prev[`ETH_HEADER_BYTES + `IPV4_HEADER_BYTES + byte_off + 1]};
                            automatic logic [15:0] new_word = {tcp_byte0, tcp_byte1};

                            tcp_checksum <= tcp_checksum - old_word + new_word;

                            header_buf_prev[`ETH_HEADER_BYTES + `IPV4_HEADER_BYTES + byte_off]     <= tcp_byte0;
                            header_buf_prev[`ETH_HEADER_BYTES + `IPV4_HEADER_BYTES + byte_off + 1] <= tcp_byte1;

                            tcp_checksum_valid_n = 0;
                        end
                    end
                end
                if (tcp_checksum_valid_n && payload_checksum != payload_checksum_prev)
                begin
                    tcp_checksum <= tcp_checksum - payload_checksum_prev + payload_checksum;
                    payload_checksum_prev <= payload_checksum;
                    tcp_checksum_valid_n = 0;
                end
                if (payload_len != prev_payload_len && pseudo_checksum_valid_n)
                begin
                    pseudo_checksum <= pseudo_checksum - prev_payload_len + payload_len;
                    prev_payload_len <= payload_len;
                    pseudo_checksum_valid_n = 0;

                end
                if (ipv4_checksum_valid_n && tcp_checksum_valid_n && pseudo_checksum_valid_n)
                    final_tcp <= pseudo_checksum + tcp_checksum;
                else
                    final_tcp <= '0;

                tcp_checksum_valid <= tcp_checksum_valid_n;
                ipv4_checksum_valid <= ipv4_checksum_valid_n;
                pseudo_checksum_valid <= pseudo_checksum_valid_n;
            end
            else
                crc32_r <= crc32_n;
            // m_axis outputs are assigned combinationally inside next-state block to respect tready
        end
    end

    // -----------------------------
    // FSM combinational next-state and outputs
    // -----------------------------
    always_comb begin
        // defaults
        state_n = state;
        // default drive zeros unless we explicitly set valid
        m_axis.tdata  = '0;
        m_axis.tkeep  = '0;
        m_axis.tvalid = 1'b0;
        m_axis.tlast  = 1'b0;

        send_byte_idx_n = send_byte_idx_r;
        crc32_n = crc32_r;
        // default done/busy are assigned by continuous assigns above

        case (state)
            // ---------------------------------------
            ST_IDLE: begin
                
                if (start) begin
                    // build header placeholders
                    // prepare send bookkeeping
                    total_frame_bytes = HEADER_BYTES + payload_len;
                    send_byte_idx_n = 0;
                    beats_total = (total_frame_bytes + AXI_BYTES_PER_BEAT - 1) / AXI_BYTES_PER_BEAT;

                    // next state -> send headers (and payload afterwards if requested)
                    state_n =  ST_CHECKSUM;
                end else begin
                    state_n = ST_IDLE;
                end
            end

            ST_CHECKSUM: begin
                // next state -> send headers (and payload afterwards if requested)
                state_n = (tcp_checksum_valid & ipv4_checksum_valid & pseudo_checksum_valid) ? ST_SEND_HDRS : ST_CHECKSUM;                
            end

            // ---------------------------------------
            ST_SEND_HDRS: begin
                if (m_axis.tready) begin
                    logic [DATA_WIDTH-1:0] out_word;
                    logic [AXI_BYTES_PER_BEAT-1:0] out_keep;
                    int b;

                    out_word = '0;
                    out_keep = '0;

                    // Fill one beat
                    for (b = 0; b < AXI_BYTES_PER_BEAT; b++) begin
                        if (send_byte_idx_n < HEADER_BYTES) begin
                            // MSB-first in tdata
                            out_word[8*(b) +: 8] = header_buf[send_byte_idx_n];
                            out_keep[b] = 1'b1;  // LSB-first tkeep
                            if (send_byte_idx_n >= `ETH_HEADER_BYTES)
                                crc32_n = crc(crc32_n, header_buf[send_byte_idx_n]);
                            send_byte_idx_n = send_byte_idx_n + 1;
                        end else begin
                            out_word[8*(b) +: 8] = 8'h00;
                            out_keep[b] = 1'b0;
                        end
                    end

                    m_axis.tdata  = out_word;
                    m_axis.tkeep  = out_keep;
                    m_axis.tvalid = |out_keep;
                    m_axis.tlast = 1'b0;
                    // Debug: show header bytes and outgoing word for diagnosis
                    for (int ii = 0; ii < HEADER_BYTES; ii+=AXI_BYTES_PER_BEAT) begin
                        // print in groups to avoid huge single-line prints
                        automatic int jmax = (ii+AXI_BYTES_PER_BEAT < HEADER_BYTES) ? ii+AXI_BYTES_PER_BEAT-1 : HEADER_BYTES-1;
                    end
                    // last beat detection
                    if (send_byte_idx_n >= HEADER_BYTES) begin
                        state_n = (payload_len == 0) ? ST_CRC32 : ST_FORWARD_PAYLOAD;
                    end else begin
                        state_n = ST_SEND_HDRS;
                    end
                end else begin
                    // wait for ready
                    m_axis.tvalid = 1'b0;
                    state_n = ST_SEND_HDRS;
                end
            end


            // ---------------------------------------
            ST_FORWARD_PAYLOAD: begin
                // Pass-through payload beats directly to m_axis, honoring backpressure.
                if (s_axis.tvalid && m_axis.tready) begin
                    automatic int bytes_this_beat = 0;
                    automatic logic [DATA_WIDTH-1:0] out_word;
                    automatic logic [AXI_BYTES_PER_BEAT-1:0] out_keep;

                    // remap tkeep: MSB-first AXI -> LSB-first capture
                    for (int kb = 0; kb < AXI_BYTES_PER_BEAT; kb++) begin
                        if (s_axis.tkeep[kb]) begin
                            bytes_this_beat += 1;
                            crc32_n = crc(crc32_n, s_axis.tdata[8*kb +: 8]);
                        end
                    end

                    m_axis.tdata  = s_axis.tdata;
                    m_axis.tkeep  = s_axis.tkeep;
                    m_axis.tvalid = 1'b1;
                    m_axis.tlast  = 1'b0;

                    send_byte_idx_n = send_byte_idx_n + bytes_this_beat;

                    // finish when we've forwarded payload_len bytes OR s_axis.tlast asserted
                    if (s_axis.tlast || (send_byte_idx_n >= total_frame_bytes)) begin
                        state_n = ST_CRC32;
                    end else begin
                        state_n = ST_FORWARD_PAYLOAD;
                    end
                end else begin
                    m_axis.tvalid = 1'b0;
                    state_n = ST_FORWARD_PAYLOAD;
                end
            end

            // ---------------------------------------
            ST_CRC32: begin
                if (m_axis.tready) begin
                    logic [DATA_WIDTH-1:0] out_word;
                    logic [AXI_BYTES_PER_BEAT-1:0] out_keep;
                    int b;

                    out_word = '0;
                    out_keep = '0;

                    // serialize CRC32, MSB-first in tdata
                    for (b = 0; b < AXI_BYTES_PER_BEAT; b++) begin
                        if (send_byte_idx_n < total_frame_bytes + 4) begin
                            // take byte from crc32, LSB-first
                            out_word[8*(b) +: 8] = crc32_r[8*(3 - (send_byte_idx_n - total_frame_bytes)) +: 8];
                            out_keep[b] = 1'b1;  // LSB-first tkeep
                            send_byte_idx_n = send_byte_idx_n + 1;
                        end else begin
                            out_word[8*(b) +: 8] = 8'h00;
                            out_keep[b] = 1'b0;
                        end
                    end

                    m_axis.tdata  = out_word;
                    m_axis.tkeep  = out_keep;
                    m_axis.tvalid = 1;
                    m_axis.tlast  = (send_byte_idx_n >= total_frame_bytes + 4);

                    state_n = (m_axis.tlast && m_axis.tready) ? ST_IDLE : ST_CRC32;
                end else begin
                    m_axis.tvalid = 1'b0;
                    state_n = ST_CRC32;
                end
            end


            default: state_n = ST_IDLE;
        endcase
    end

endmodule
