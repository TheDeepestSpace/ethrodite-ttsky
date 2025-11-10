`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"
`include "tcp_sender.sv"

`define NUM_PACKETS 10

module tcp_sender_tb;

    parameter DATA_WIDTH = `INPUTWIDTH;

    localparam WINDOW_SIZE = 16'h1000;
    localparam ETH_TYPE_IPV4 = `ETH_TYPE_IPV4;

    // Clock & reset
    logic clk;
    logic rst_n;

    // AXI interfaces
    axi_stream_if s_axis_if();
    axi_stream_if m_axis_if();

    // DUT controls
    logic                     start;

    logic busy, has_payload;
    tcp_packet_info_s tb_pkt;

    // Capture buffers
    logic [7:0] rx_buffer[$];
    logic [7:0] expected_payload[$];
    logic [7:0] expected_frame_bytes[$];
    int expected_payload_len;
    int expected_frame_len;

    // -----------------------------
    // DUT
    // -----------------------------
    tcp_sender dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .i_pkt(tb_pkt),
        .s_axis(s_axis_if),
        .m_axis(m_axis_if),
        .busy(busy)
        );

    // Clock
    initial clk = 0;
    always #5 clk = ~clk;

    // Reset
    initial begin
        rst_n = 0;
        repeat (5) @(posedge clk);
        rst_n = 1;
        repeat (5) @(posedge clk);
    end

    // Capture bytes emitted by DUT
    always_ff @(posedge clk or negedge rst_n) begin
        if (m_axis_if.tvalid) begin
            rx_buffer.push_back(m_axis_if.tdata);
        end
    end

    // Send payload beat into s_axis_if
    task send_word(input logic [DATA_WIDTH-1:0] tdata, input bit tlast);
        s_axis_if.tdata  = tdata;
        s_axis_if.tvalid = 1'b1;
        s_axis_if.tlast  = tlast;
        do @(posedge clk); while (!s_axis_if.tready);
        s_axis_if.tvalid = 0;
        s_axis_if.tlast  = 0;
    endtask

    // Build expected frame using field macros
    task build_expected_packet(
        input logic [47:0] t_src_mac,
        input logic [47:0] t_dst_mac,
        input logic [31:0] t_src_ip,
        input logic [31:0] t_dst_ip,
        input logic [15:0] t_src_port,
        input logic [15:0] t_dst_port,
        input logic [31:0] t_seq_num,
        input logic [31:0] t_ack_num,
        input logic [7:0]  t_flags,
        input bit          t_has_payload,
        input logic [7:0]  t_payload_bytes [0:255],
        input int          t_payload_len,
        input logic [15:0] t_tcp_checksum
    );
        automatic logic [7:0] bytes [0:4095];
        automatic int pkt_len;
        automatic int ip_hdr_start = `ETH_HEADER_BYTES;
        automatic int tcp_start = ip_hdr_start + `IPV4_HEADER_MIN_BYTES;
        automatic int ipv4_total_len = `IPV4_HEADER_MIN_BYTES + `TCP_HEADER_MIN_LEN + t_payload_len;
        automatic int sum, payload_sum;
        automatic logic [31:0] t_crc32 = 32'hFFFFFFFF;
        begin
            // Ethernet header
            for (int i=0; i<`MAC_ADDR_BYTES; i++)
                bytes[`ETH_DST_MAC_BASE + i] = t_dst_mac[47-8*i -: 8];
            for (int i=0; i<`MAC_ADDR_BYTES; i++)
                bytes[`ETH_SRC_MAC_BASE + i] = t_src_mac[47-8*i -: 8];
            bytes[`ETH_TYPE_BASE + 0] = ETH_TYPE_IPV4[15:8];
            bytes[`ETH_TYPE_BASE + 1] = ETH_TYPE_IPV4[7:0];

            // IPv4 header
            bytes[ip_hdr_start + `IPV4_VERSION_IHL_OFFSET] = {`IPV4_VERSION_DEFAULT, `IPV4_IHL_DEFAULT};
            bytes[ip_hdr_start + `IPV4_DSCP_ECN_OFFSET] = 8'h00;
            bytes[ip_hdr_start + `IPV4_TOTAL_LENGTH_MSB_OFFSET] = ipv4_total_len[15:8];
            bytes[ip_hdr_start + `IPV4_TOTAL_LENGTH_LSB_OFFSET] = ipv4_total_len[7:0];
            bytes[ip_hdr_start + `IPV4_IDENT_MSB_OFFSET] = 8'h00;
            bytes[ip_hdr_start + `IPV4_IDENT_LSB_OFFSET] = 8'h00;
            bytes[ip_hdr_start + `IPV4_FLAGS_FRAG_MSB_OFFSET] = 8'h40;
            bytes[ip_hdr_start + `IPV4_FLAGS_FRAG_LSB_OFFSET] = 8'h00;
            bytes[ip_hdr_start + `IPV4_TTL_OFFSET] = 8'd64;
            bytes[ip_hdr_start + `IPV4_PROTOCOL_OFFSET] = `IPV4_PROTOCOL_TCP;
            bytes[ip_hdr_start + `IPV4_CHECKSUM_MSB_OFFSET] = 8'h00;
            bytes[ip_hdr_start + `IPV4_CHECKSUM_LSB_OFFSET] = 8'h00;
            for (int i=0; i<`IPV4_ADDR_BYTES; i++)
                bytes[ip_hdr_start + `IPV4_SRC_IP_OFFSET + i] = t_src_ip[31-8*i -: 8];
            for (int i=0; i<`IPV4_ADDR_BYTES; i++)
                bytes[ip_hdr_start + `IPV4_DST_IP_OFFSET + i] = t_dst_ip[31-8*i -: 8];

            // TCP header
            bytes[tcp_start + `TCP_SRC_PORT_BASE] = t_src_port[15:8];
            bytes[tcp_start + `TCP_SRC_PORT_BASE + 1] = t_src_port[7:0];
            bytes[tcp_start + `TCP_DST_PORT_BASE] = t_dst_port[15:8];
            bytes[tcp_start + `TCP_DST_PORT_BASE + 1] = t_dst_port[7:0];
            for (int i=0; i<4; i++)
                bytes[tcp_start + `TCP_SEQ_NUM_BASE + i] = t_seq_num[31-8*i -: 8];
            for (int i=0; i<4; i++)
                bytes[tcp_start + `TCP_ACK_NUM_BASE + i] = t_ack_num[31-8*i -: 8];
            bytes[tcp_start + `TCP_DATA_OFFSET_BASE] = 8'h50;
            bytes[tcp_start + `TCP_FLAGS_BASE] = t_flags;
            bytes[tcp_start + `TCP_WINDOW_SIZE_BASE] = WINDOW_SIZE[15:8];
            bytes[tcp_start + `TCP_WINDOW_SIZE_BASE + 1] = WINDOW_SIZE[7:0];
            bytes[tcp_start + `TCP_CHECKSUM_BASE] = 8'h00;
            bytes[tcp_start + `TCP_CHECKSUM_BASE + 1] = 8'h00;
            bytes[tcp_start + `TCP_URGENT_PTR_BASE] = 8'h00;
            bytes[tcp_start + `TCP_URGENT_PTR_BASE + 1] = 8'h00;

            // Payload
            for (int i=0; i<t_payload_len; i++)
                bytes[tcp_start + `TCP_HEADER_MIN_LEN + i] = t_payload_bytes[i];

            pkt_len = tcp_start + `TCP_HEADER_MIN_LEN + t_payload_len;

            // IPv4 checksum
            sum = 0;
            for (int i=ip_hdr_start; i<ip_hdr_start + `IPV4_HEADER_MIN_BYTES; i+=2) begin
                sum += {bytes[i], bytes[i+1]};
            end
            while (sum >> 16)
                sum = (sum & 16'hFFFF) + (sum >> 16);
            sum = ~sum;
            bytes[ip_hdr_start + `IPV4_CHECKSUM_MSB_OFFSET] = sum[15:8];
            bytes[ip_hdr_start + `IPV4_CHECKSUM_LSB_OFFSET] = sum[7:0];

            sum = 0;

            // ---------- 1. Pseudo header (from IPv4) ----------
            sum += {bytes[ip_hdr_start + `IPV4_SRC_IP_OFFSET + 0], bytes[ip_hdr_start + `IPV4_SRC_IP_OFFSET + 1]};
            sum += {bytes[ip_hdr_start + `IPV4_SRC_IP_OFFSET + 2], bytes[ip_hdr_start + `IPV4_SRC_IP_OFFSET + 3]};
            sum += {bytes[ip_hdr_start + `IPV4_DST_IP_OFFSET + 0], bytes[ip_hdr_start + `IPV4_DST_IP_OFFSET + 1]};
            sum += {bytes[ip_hdr_start + `IPV4_DST_IP_OFFSET + 2], bytes[ip_hdr_start + `IPV4_DST_IP_OFFSET + 3]};
            sum += (`IPV4_TCP_PROTO<<8)+(t_payload_len + `TCP_HEADER_MIN_LEN); // TCP length (header + payload)

            // ---------- 2. TCP header ----------
            for (int i = tcp_start; i < tcp_start + `TCP_HEADER_MIN_LEN; i += 2) begin
                // Handle last odd byte (if payload length is odd)
                if (i + 1 >= tcp_start + `TCP_HEADER_MIN_LEN)
                    sum += {bytes[i], 8'h00};
                else
                    sum += {bytes[i], bytes[i+1]};
            end

            // ---------3. TCP paylaod -----------
            for (int i = 0; i < t_payload_len; i += 2) begin
                // Handle last odd byte (if payload length is odd)
                if (i + 1 >= t_payload_len)
                    payload_sum += {t_payload_bytes[i], 8'h00};
                else
                    payload_sum += {t_payload_bytes[i], t_payload_bytes[i+1]};
            end
            
            sum += payload_sum;

            while (sum >> 16)
                sum = (sum & 16'hFFFF) + (sum >> 16);
            sum = ~sum;

            bytes[tcp_start + `TCP_CHECKSUM_BASE] = sum[15:8];
            bytes[tcp_start + `TCP_CHECKSUM_BASE + 1] = sum[7:0];


            for (int i = 0; i < pkt_len; i++)
                t_crc32 = crc(t_crc32, bytes[i]);

            t_crc32 = ~t_crc32;
            //adding the CRC32
            bytes[pkt_len + 3] = t_crc32[31:24];
            bytes[pkt_len + 2] = t_crc32[23:16];
            bytes[pkt_len + 1] = t_crc32[15:8];
            bytes[pkt_len + 0] = t_crc32[7:0];

            // Store expected frame and payload
            expected_frame_bytes = {};
            for (int i=0; i<pkt_len + `CRC32_WIDTH; i++)
                expected_frame_bytes.push_back(bytes[i]);
            expected_frame_len = pkt_len + `CRC32_WIDTH;

            expected_payload = {};
            for (int i=0; i<t_payload_len; i++)
                expected_payload.push_back(t_payload_bytes[i]);
            expected_payload_len = t_payload_len;
        end
    endtask

    // Start pulse + optional payload streaming
    task send_instruction_and_payload();
        start = 1'b1;
        @(posedge clk);
        start = 1'b0;
        if (has_payload) begin
            for (int n=0; n<tb_pkt.payload_len; n++) begin
                send_word(expected_payload[n], n == tb_pkt.payload_len-1);
            end
        end
    endtask

    // Main test
    initial begin
        @(posedge rst_n);
        m_axis_if.tready <= 1'b1;
        s_axis_if.tvalid <= 1'b0;
        s_axis_if.tlast  <= 1'b0;
        $display("Starting TCP packet tests...");

        for (int n=0; n<`NUM_PACKETS; n++) begin
            automatic logic [47:0] tb_src_mac = 48'h112233445566;
            automatic logic [47:0] tb_dst_mac = 48'hAABBCCDDEEFF;
            automatic logic [31:0] tb_src_ip  = 32'hC0A80101;
            automatic logic [31:0] tb_dst_ip  = 32'hC0A80102;
            automatic logic [15:0] tb_src_port = 16'd5000 + n;
            automatic logic [15:0] tb_dst_port = 16'd80;
            automatic logic [31:0] tb_seq = 32'h12345678 + n;
            automatic logic [31:0] tb_ack = 32'h87654321;
            automatic logic [7:0]  tb_flags = 8'b00010000; // ACK
            automatic logic tb_has_payload = (n % 2);
            automatic logic [7:0] tb_payload [0:255];
            automatic int tb_payload_len = tb_has_payload ? $urandom_range(0, 1000) : 0;
            automatic int timeout = 5000;
            automatic int waited = 0;
            automatic bit pass = 1;
            automatic int payload_checksum;

            rx_buffer = {};
            for (int i=0; i<tb_payload_len; i++)
                tb_payload[i] = i[7:0];
            

            payload_checksum = 0;
            for (int i = 0; i < tb_payload_len; i += 2) begin
                // Handle last odd byte (if payload length is odd)
                if (i + 1 >= tb_payload_len)
                    payload_checksum += {tb_payload[i], 8'h00};
                else
                    payload_checksum += {tb_payload[i], tb_payload[i+1]};
            end
            
            while (payload_checksum >> 16)
                payload_checksum = (payload_checksum & 16'hFFFF) + (payload_checksum >> 16);            

            build_expected_packet(tb_src_mac, tb_dst_mac,
                                  tb_src_ip, tb_dst_ip,
                                  tb_src_port, tb_dst_port,
                                  tb_seq, tb_ack, tb_flags,
                                  tb_has_payload, tb_payload, tb_payload_len,
                                  payload_checksum[15:0]);
            has_payload = tb_has_payload;
            tb_pkt.window  = WINDOW_SIZE;
            tb_pkt.tcp_checksum = payload_checksum[15:0];
            tb_pkt.src_mac      = tb_src_mac;
            tb_pkt.dst_mac      = tb_dst_mac;
            tb_pkt.src_ip       = tb_src_ip;
            tb_pkt.dst_ip       = tb_dst_ip;
            tb_pkt.src_port     = tb_src_port;
            tb_pkt.dst_port     = tb_dst_port;
            tb_pkt.seq_num      = tb_seq;
            tb_pkt.ack_num      = tb_ack;
            tb_pkt.tcp_flags    = tb_flags;
            tb_pkt.payload_len  = tb_payload_len;

            @(posedge clk);
            send_instruction_and_payload();

            repeat(1500) @(posedge clk);

            if (rx_buffer.size() != expected_frame_len) begin
                $display("ERROR: frame length mismatch: expected %0d got %0d",
                         expected_frame_len, rx_buffer.size());
                pass = 0;
            end else begin
                for (int b=0; b<expected_frame_len; b++)
                    begin
                    if (rx_buffer[b] !== expected_frame_bytes[b]) begin
                        $display("Mismatch @ byte %0d: exp=%02h got=%02h",
                                 b, expected_frame_bytes[b], rx_buffer[b]);
                        pass = 0;
                    end
                end
            end

            if (pass)
                $display("[%0t] PASS: TCP frame #%0d OK (payload=%0d)",
                         $time, n, tb_payload_len);
            else
                $display("[%0t] FAIL: TCP frame #%0d mismatch",
                         $time, n);

            repeat (5) @(posedge clk);
        end

        $display("TCP test complete.");
        $stop(0);
    end

endmodule
