`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"   
`include "tcp_handler.sv"

`define NUM_PACKETS 10

module tcp_handler_tb;

    // Parameters (match your DUT)
    parameter int DATA_WIDTH = `INPUTWIDTH;               // must be defined in includes
    parameter int BYTES = DATA_WIDTH/8;

    // Clock & reset
    logic clk;
    logic rst_n;

    // AXI interfaces (interfaces assumed from your setup)
    axi_stream_if s_axis_if();
    axi_stream_if m_axis_if();

    // DUT metadata outputs (matching the tcp_handler you posted)
    logic        meta_valid, meta_ready;
    logic [15:0] meta_src_port;
    logic [15:0] meta_dst_port;
    logic [31:0] meta_seq_num;
    logic [31:0] meta_ack_num;
    logic [7:0]  meta_flags;
    logic [15:0] meta_window_size;
    logic [15:0] meta_payload_len;
    logic        meta_checksum_ok;
    logic        meta_checksum_valid;

    //DUT INPUT
    logic [15:0] in_pseudo_header;

    // -----------------------------
    // DUT instantiation - change name/params/path to match your module
    // Example assumes tcp_handler exists and has the ports shown earlier.
    tcp_handler #(
        .DATA_WIDTH(DATA_WIDTH)
    ) dut (
        .clk(clk),
        .rst_n(rst_n),
        .s_axis(s_axis_if),
        .m_axis(m_axis_if),
        .meta_valid(meta_valid),
        .meta_ready(meta_ready),
        .meta_src_port(meta_src_port),
        .meta_dst_port(meta_dst_port),
        .meta_seq_num(meta_seq_num),
        .meta_ack_num(meta_ack_num),
        .meta_flags(meta_flags),
        .meta_window_size(meta_window_size),
        .meta_payload_len(meta_payload_len),
        .meta_pseudo_header(in_pseudo_header),
        .meta_checksum_ok(meta_checksum_ok),
        .meta_checksum_valid(meta_checksum_valid)
    );

    // -----------------------------
    // Buffers for verification
    logic [7:0] rx_buffer[$];         // received payload from m_axis
    logic [7:0] expected_payload[$];  // expected payload extracted from generator
    int expected_payload_len;

    // Clock generation
    initial clk = 0;
    always #5 clk = ~clk; // 100 MHz-ish

    // Reset
    initial begin
        rst_n = 0;
        repeat (5) @(posedge clk);
        rst_n = 1;
        repeat (5) @(posedge clk);
    end

    // Ensure interfaces default low
    initial begin
        s_axis_if.tdata  = '0;
        s_axis_if.tkeep  = '0;
        s_axis_if.tvalid = 0;
        s_axis_if.tlast  = 0;
        m_axis_if.tready = 1; // allow downstream always ready in this TB
        meta_ready = 0;
    end

    // Capture m_axis payload bytes as they appear
    always_ff @(posedge clk or negedge rst_n) begin
        if (m_axis_if.tvalid && m_axis_if.tready) begin
            for (int i = 0; i < BYTES; i++) begin
                if (m_axis_if.tkeep[i]) begin
                    // extract byte: big-endian packing assumed
                    rx_buffer.push_back(m_axis_if.tdata[(8*i) +: 8]);
                end
            end
        end
    end

    // -----------------------------
    // Helper: send single AXI4-Stream word
    task automatic send_word(
        input logic [DATA_WIDTH-1:0] tdata,
        input logic [BYTES-1:0]      tkeep,
        input bit                    tlast
    );
        begin
            s_axis_if.tdata  = tdata;
            s_axis_if.tkeep  = tkeep;
            s_axis_if.tvalid = 1'b1;
            s_axis_if.tlast  = tlast;
            // wait for ready (handshake)
            do @(posedge clk); while (!s_axis_if.tready);
            // deassert after handshake
            s_axis_if.tvalid = 1'b0;
            s_axis_if.tlast  = 1'b0;
            s_axis_if.tdata  = '0;
            s_axis_if.tkeep  = '0;
        end
    endtask

    // -----------------------------
    // Generator: produces a TCP packet byte array and expected metadata
    task automatic gen_random_tcp_packet(
        input logic [15:0] in_pseudo_header,
        output byte         bytes[],             // byte array containing only TCP header+payload (no ethernet/ip)
        output int          total_bytes,         // total bytes in bytes[]
        output int          start_offset,        // random offset before TCP header inside bytes[]
        output logic [15:0] exp_src_port,
        output logic [15:0] exp_dst_port,
        output logic [31:0] exp_seq_num,
        output logic [31:0] exp_ack_num,
        output logic [7:0]  exp_flags,
        output logic [15:0] exp_window_size,
        output logic [15:0] exp_urgent_ptr,
        output logic [15:0] exp_hdr_checksum
    );
        // params
        localparam int MIN_OFFSET      = 0;
        localparam int MAX_OFFSET      = BYTES-1;    // allow up to one-beat misalignment
        localparam int MIN_PAYLOAD_LEN = 4;
        localparam int MAX_PAYLOAD_LEN = 64;
        localparam int TCP_HEADER_LEN  = 20;         // no options

        int payload_len;
        int p;
        int unsigned sum = 0;
        begin
            start_offset     = $urandom_range(MIN_OFFSET, MAX_OFFSET);
            exp_src_port     = $urandom;
            exp_dst_port     = $urandom;
            exp_seq_num      = $urandom;
            exp_ack_num      = $urandom;
            exp_flags        = $urandom_range(0, 8'h3F);
            exp_window_size  = $urandom;
            exp_urgent_ptr   = $urandom;
            payload_len      = $urandom_range(MIN_PAYLOAD_LEN, MAX_PAYLOAD_LEN);

            total_bytes = start_offset + TCP_HEADER_LEN + payload_len;
            bytes = new[total_bytes];

            // random prefix padding
            for (int i = 0; i < start_offset; i++)
                bytes[i] = $urandom_range(0,255);

            p = start_offset;
            // TCP header fields (big-endian)
            bytes[p+0] = exp_src_port[15:8];
            bytes[p+1] = exp_src_port[7:0];
            bytes[p+2] = exp_dst_port[15:8];
            bytes[p+3] = exp_dst_port[7:0];
            bytes[p+4] = exp_seq_num[31:24];
            bytes[p+5] = exp_seq_num[23:16];
            bytes[p+6] = exp_seq_num[15:8];
            bytes[p+7] = exp_seq_num[7:0];
            bytes[p+8]  = exp_ack_num[31:24];
            bytes[p+9]  = exp_ack_num[23:16];
            bytes[p+10] = exp_ack_num[15:8];
            bytes[p+11] = exp_ack_num[7:0];
            bytes[p+12] = 8'h50; // data offset = 5 (20 bytes), no options
            bytes[p+13] = exp_flags;
            bytes[p+14] = exp_window_size[15:8];
            bytes[p+15] = exp_window_size[7:0];
            bytes[p+16] = 8'h00; // checksum placeholder
            bytes[p+17] = 8'h00;
            bytes[p+18] = exp_urgent_ptr[15:8];
            bytes[p+19] = exp_urgent_ptr[7:0];

            // payload
            for (int i = p + TCP_HEADER_LEN; i < total_bytes; i++)
            begin
                bytes[i] = $urandom_range(0,255);
            end


            // Compute simple header checksum (header-only one's complement)
            sum = in_pseudo_header;
            for (int i = p; i < p + total_bytes; i += 2) begin
                int unsigned word;
                
                if (i + 1 < p + total_bytes) begin
                    // Normal 16-bit word
                    word = {bytes[i], bytes[i+1]};
                end else begin
                    // Last byte, pad low byte with 0
                    word = {bytes[i], 8'h00};
                end
                
                sum += word;
                sum = (sum & 16'hFFFF) + (sum >> 16); // 1's complement folding
            end
            exp_hdr_checksum = ~sum[15:0];
            bytes[p+16] = exp_hdr_checksum[15:8];
            bytes[p+17] = exp_hdr_checksum[7:0];
        end
    endtask

    // -----------------------------
    // send_packet: use generator and stream out AXI words,
    // and record expected metadata & payload for verification
    task automatic send_packet(
        input logic [15:0] in_pseudo_header,
        output logic [15:0] out_exp_src_port,
        output logic [15:0] out_exp_dst_port,
        output logic [31:0] out_exp_seq_num,
        output logic [31:0] out_exp_ack_num,
        output logic [7:0]  out_exp_flags,
        output logic [15:0] out_exp_window_size,
        output logic [15:0] out_exp_hdr_checksum
    );
        byte pkt[];
        int total_bytes, start_offset;
        logic [DATA_WIDTH-1:0] tdata;
        logic [BYTES-1:0]      tkeep;
        int i,b;
        int tcp_header_start;
        logic [15:0] exp_urgent_ptr;

        begin
            // generate packet bytes and expected metadata
            gen_random_tcp_packet(
                in_pseudo_header,
                pkt, total_bytes, start_offset,
                out_exp_src_port, out_exp_dst_port,
                out_exp_seq_num, out_exp_ack_num,
                out_exp_flags, out_exp_window_size,
                exp_urgent_ptr, out_exp_hdr_checksum
            );
            // Note: we don't need urgent_ptr for verification here; omitted from outputs

            // Save expected payload bytes (payload is bytes after header)
            expected_payload = {};
            tcp_header_start = start_offset;
            expected_payload_len = total_bytes - (tcp_header_start + 20);
            for (int k = tcp_header_start + 20; k < total_bytes; k++) expected_payload.push_back(pkt[k]);

            // Stream out the full byte array as AXI words (including pre-padding bytes)
            for (i = 0; i < total_bytes; i += BYTES) begin
                int valid_in_beat = BYTES;
                tdata = '0;
                tkeep = '0;
                if (i + BYTES > total_bytes)
                    valid_in_beat = total_bytes - i;

                for (b = 0; b < BYTES; b++) begin
                    int byte_idx = i + b;

                    if (i == 0 && b < start_offset) begin
                        tkeep[b] = 1'b0; // pre-offset invalid
                    end else if (b < valid_in_beat) begin
                        tdata = tdata | (pkt[byte_idx] << ((b)*8));
                        tkeep[b] = 1'b1;
                    end else begin
                        tkeep[b] = 1'b0; // post-total_bytes invalid
                    end
                end

                // tlast on the last beat
                send_word(tdata, tkeep, (i + BYTES >= total_bytes));
            end
        end
    endtask

    // -----------------------------
    // Test driver: send NUM_PACKETS randomized packets and check DUT outputs
    initial begin
        // wait for reset release
        @(posedge rst_n);
        // make m_axis ready to consume
        m_axis_if.tready <= 1;
        $display("Starting TCP parser test...");

        for (int pkt_i = 0; pkt_i < `NUM_PACKETS; pkt_i++) begin
            // expected metadata
            logic [15:0] exp_src_port, exp_dst_port, exp_window;
            logic [31:0] exp_seq_num, exp_ack_num;
            logic [7:0]  exp_flags;
            logic [15:0] exp_hdr_chk;
            automatic int timeout = 1000;
            automatic int waited = 0;
            automatic bit meta_ok = 1;
            
            // clear capture buffer
            rx_buffer = {};
            expected_payload = {};
            in_pseudo_header = $urandom;
            meta_ready = 0;

            // send a randomized packet and obtain expected metadata & payload
            send_packet(in_pseudo_header, exp_src_port, exp_dst_port, exp_seq_num, exp_ack_num, exp_flags, exp_window, exp_hdr_chk);
            
            repeat(100) @(posedge clk);

            if (!meta_valid) begin
                $display("ERROR: DUT did not assert meta_valid within timeout for packet %0d", pkt_i);
            end
            // Check metadata fields
            if (meta_src_port !== exp_src_port) begin
                $display("META MISMATCH: src_port expected %h got %h", exp_src_port, meta_src_port);
                meta_ok = 0;
            end
            if (meta_dst_port !== exp_dst_port) begin
                $display("META MISMATCH: dst_port expected %h got %h", exp_dst_port, meta_dst_port);
                meta_ok = 0;
            end
            if (meta_seq_num !== exp_seq_num) begin
                $display("META MISMATCH: seq expected 0x%08x got 0x%08x", exp_seq_num, meta_seq_num);
                meta_ok = 0;
            end
            if (meta_ack_num !== exp_ack_num) begin
                $display("META MISMATCH: ack expected 0x%08x got 0x%08x", exp_ack_num, meta_ack_num);
                meta_ok = 0;
            end
            if (meta_flags !== exp_flags) begin
                $display("META MISMATCH: flags expected 0x%02x got 0x%02x", exp_flags, meta_flags);
                meta_ok = 0;
            end
            if (meta_window_size !== exp_window) begin
                $display("META MISMATCH: window expected %0d got %0d", exp_window, meta_window_size);
                meta_ok = 0;
            end
            if (meta_payload_len !== expected_payload.size()) begin
                $display("META MISMATCH: forwarded length expected %h got %h", expected_payload.size(), meta_payload_len);
                meta_ok = 0;
            end

            while (!meta_checksum_valid && waited < timeout) begin
                @(posedge clk);
                waited++;
            end

            // Note: checksum semantics depend on DUT: we compared header-only checksum computed in generator
            if (meta_checksum_ok !== 1'b1) begin
                // Many implementations return meta_checksum_ok = 1 if sum==0xFFFF; adjust if DUT semantics differ
                // We'll just print checksum values for debugging
                $display("ERROR: DUT checksum_ok = %0b ; expected header checksum 0x%04x", meta_checksum_ok, exp_hdr_chk);
                meta_ok = 0;
            end

            // Check forwarded payload length & contents
            if (rx_buffer.size() !== expected_payload.size()) begin
                $display("PAYLOAD SIZE MISMATCH: expected %0d bytes, got %0d bytes", expected_payload.size(), rx_buffer.size());
            end else begin
                automatic bit payload_ok = 1;
                for (int k = 0; k < expected_payload.size(); k++) begin
                    if (rx_buffer[k] !== expected_payload[k]) begin
                        payload_ok = 0;
                        $display("PAYLOAD MISMATCH at byte %0d: expected %02x got %02x", k, expected_payload[k], rx_buffer[k]);
                    end
                end
                if (payload_ok && meta_ok) begin
                    $display("[%0t] PASS packet %0d: metadata and payload match", $time, pkt_i);
                end else begin
                    $display("[%0t] FAIL packet %0d", $time, pkt_i);
                    if (!meta_ok) $display("  metadata mismatch");
                    if (expected_payload.size() != rx_buffer.size()) $display("  payload size mismatch");
                end
            end

            // small gap between packets
            meta_ready = 1;
            @(posedge clk);
            meta_ready = 0;
            
            repeat (5) @(posedge clk);
        end

        $display("All tests complete.");
        $stop(0);
    end

endmodule
