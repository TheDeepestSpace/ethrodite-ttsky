`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"
`include "ethernet_ipv4_handler.sv"

`define ETH_TYPE_IPV4 16'h0800
`define NUM_PACKETS 10

module ethernet_ipv4_handler_tb;

    parameter DATA_WIDTH = `INPUTWIDTH;
    parameter BYTES = `AXI_BYTES(DATA_WIDTH);

    // Clock & reset
    logic clk;
    logic rst_n;

    // AXI interfaces
    axi_stream_if s_axis_if();
    axi_stream_if m_axis_if();

    // Metadata outputs
    logic        meta_valid;
    logic [47:0] meta_dst_mac;
    logic [47:0] meta_src_mac;
    logic [31:0] meta_src_ip;
    logic [31:0] meta_dst_ip;
    logic [7:0]  meta_protocol;
    logic [15:0] meta_total_length;
    logic [15:0] meta_pseudo_header;
    logic        meta_crc32;
    logic        meta_checksum_ok;
    logic        meta_ethertype_ok;
    logic        meta_length_ok;
    logic        meta_crc32_valid;
    logic        meta_ready;

    // -----------------------------
    // DUT instantiation
    ethernet_ipv4_handler #(.DATA_WIDTH(DATA_WIDTH)) dut (
        .clk(clk),
        .rst_n(rst_n),
        .s_axis(s_axis_if),
        .m_axis(m_axis_if),
        .meta_valid(meta_valid),
        .meta_dst_mac(meta_dst_mac),
        .meta_src_mac(meta_src_mac),
        .meta_src_ip(meta_src_ip),
        .meta_dst_ip(meta_dst_ip),
        .meta_protocol(meta_protocol),
        .meta_total_length(meta_total_length),
        .meta_checksum_ok(meta_checksum_ok),
        .meta_ethertype_ok(meta_ethertype_ok),
        .meta_length_ok(meta_length_ok),
        .meta_crc32_ok(meta_crc32),
        .meta_crc32_valid(meta_crc32_valid),
        .meta_pseudo_header(meta_pseudo_header),
        .meta_ready(meta_ready)
    );

    localparam ETH_TYPE_IPV4 = `ETH_TYPE_IPV4;
    localparam pkt_len = `ETH_HEADER_BYTES + `IPV4_IHL_DEFAULT*4;
    localparam num_beats = (pkt_len + BYTES - 1) / BYTES;

    localparam MAX_RX_BYTES = 1500;

    // -----------------------------
    // Payload storage using queues
    logic [7:0] rx_buffer[$];         // received payload
    logic [7:0] expected_payload[$];  // expected payload
    integer payload_len;

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

    // Capture m_axis payload
    always_ff @(posedge clk or negedge rst_n) begin
        if (m_axis_if.tvalid) begin
            // Loop over all bytes in tdata
            for (int i = 0; i < BYTES; i++) begin
                if (m_axis_if.tkeep[i]) begin
                    rx_buffer.push_back(m_axis_if.tdata[8*(i) +: 8]);
                end
            end
        end
    end

    // -----------------------------
    // Send single AXI word
    task send_word(input logic [DATA_WIDTH-1:0] tdata,input logic [DATA_WIDTH/8-1:0] tkeep, input bit tlast);
        s_axis_if.tdata  = tdata;
        s_axis_if.tkeep  = tkeep;
        s_axis_if.tvalid = 1'b1;
        s_axis_if.tlast  = tlast;
        // Wait until ready
        do @(posedge clk); while (!s_axis_if.tready);
        s_axis_if.tvalid = 1'b0;
        s_axis_if.tlast  = 1'b0;

    endtask

    // -----------------------------
    // IPv4 checksum function
    function automatic [15:0] ipv4_checksum(input logic [7:0] hdr_bytes[], input int len);
        int i;
        int sum;
        sum = 0;
        for (i = 0; i < len; i = i + 2) begin
            automatic logic [15:0] word;
            if (i == 10) word = 16'h0000;
            else word = {hdr_bytes[i], (i+1 < len) ? hdr_bytes[i+1] : 8'h00};
            sum = sum + word;
        end
        while (sum >> 16) sum = (sum & 16'hFFFF) + (sum >> 16);
        ipv4_checksum = ~sum[15:0];
    endfunction

    // -----------------------------
    // Send one packet and store expected metadata
    // -----------------------------
    task send_packet(
        input bit valid_checksum,
        output logic [47:0] exp_dst_mac,
        output logic [47:0] exp_src_mac,
        output logic [31:0] exp_src_ip,
        output logic [31:0] exp_dst_ip,
        output logic [7:0]  exp_protocol,
        output logic [15:0] exp_total_length,
        output logic [15:0] exp_pseudo_header,
        output logic        exp_crc32_ok
    );
        int i, j;
        automatic logic [7:0] bytes [0:65535]; // large enough for max IPv4 packet
        automatic int ip_hdr_start = `ETH_HEADER_BYTES;
        automatic int ipv4_total_len;
        automatic int pkt_len;
        automatic int num_beats;
        automatic logic [31:0] exp_crc32;
        automatic logic [31:0] tcp_chksum_acc;

        // Ethernet header
        for (i=0; i<6; i++) begin
            bytes[i] = $urandom;
            exp_dst_mac[47-8*i -: 8] = bytes[i];
        end
        for (i=6; i<12; i++) begin
            bytes[i] = $urandom;
            exp_src_mac[47-8*(i-6) -: 8] = bytes[i];
        end
        bytes[12] = ETH_TYPE_IPV4[15:8];
        bytes[13] = ETH_TYPE_IPV4[7:0];

        // IPv4 header
        bytes[ip_hdr_start + 0] = {4'h4, `IPV4_IHL_DEFAULT};
        bytes[ip_hdr_start + 1] = 8'h00;
        ipv4_total_len = `IPV4_IHL_DEFAULT*4 + $urandom_range(20, 100); // header + payload
        bytes[ip_hdr_start + 2] = (ipv4_total_len >> 8) & 8'hFF;
        bytes[ip_hdr_start + 3] = ipv4_total_len & 8'hFF;
        bytes[ip_hdr_start + 4] = 8'h00;
        bytes[ip_hdr_start + 5] = 8'h00;
        bytes[ip_hdr_start + 6] = 8'h40;
        bytes[ip_hdr_start + 7] = 8'h00;
        bytes[ip_hdr_start + 8] = 8'h40;  // TTL
        bytes[ip_hdr_start + 9] = 8'h11;  // UDP
        bytes[ip_hdr_start +10] = 8'h00;
        bytes[ip_hdr_start +11] = 8'h00;

        // Source IP
        for (i=ip_hdr_start+12; i<ip_hdr_start+16; i++) begin
            bytes[i] = $urandom;
            exp_src_ip[31-8*(i-(ip_hdr_start+12)) -: 8] = bytes[i];
        end

        // Destination IP
        for (i=ip_hdr_start+16; i<ip_hdr_start+20; i++) begin
            bytes[i] = $urandom;
            exp_dst_ip[31-8*(i-(ip_hdr_start+16)) -: 8] = bytes[i];
        end

        exp_protocol = bytes[ip_hdr_start+9];
        exp_total_length = ipv4_total_len;

        // Compute checksum
        if (valid_checksum) begin
            automatic logic [15:0] csum;
            csum = ipv4_checksum(bytes[ip_hdr_start +: `IPV4_IHL_DEFAULT*4], `IPV4_IHL_DEFAULT*4);
            bytes[ip_hdr_start +10] = csum[15:8];
            bytes[ip_hdr_start +11] = csum[7:0];
        end

        // --- pseudo-header ---
        tcp_chksum_acc = exp_src_ip[31:16] + exp_src_ip[15:0]
                        + exp_dst_ip[31:16] + exp_dst_ip[15:0]
                        + `IPV4_TCP_PROTO + (ipv4_total_len - `IPV4_IHL_DEFAULT*4); // TCP length

        // --- final wrap-around ---
        exp_pseudo_header = tcp_chksum_acc[15:0] + (tcp_chksum_acc >> 16);
        exp_pseudo_header = exp_pseudo_header[15:0] + (exp_pseudo_header >> 16);

        // Payload: fill with random data
        expected_payload = {};
        payload_len = ipv4_total_len - `IPV4_IHL_DEFAULT*4;

        for (i=`ETH_HEADER_BYTES + `IPV4_IHL_DEFAULT*4; i<`ETH_HEADER_BYTES + ipv4_total_len; i++) begin
            bytes[i] = $urandom;
            expected_payload.push_back(bytes[i]);
        end
        
        exp_crc32 = 32'hFFFFFFFF;
        for (i=`ETH_HEADER_BYTES; i<`ETH_HEADER_BYTES + ipv4_total_len; i++) begin
            exp_crc32 = crc(exp_crc32, bytes[i]);
        end

        //all packets are valid for this testbench:
        exp_crc32_ok = 1'b1;

        for (i=0; i<`CRC32_WIDTH; i++) begin
            bytes[`ETH_HEADER_BYTES + ipv4_total_len+i] = exp_crc32[`CRC32_WIDTH*8-1-8*i -: 8];
        end

        // Total packet length in bytes
        pkt_len = `ETH_HEADER_BYTES + ipv4_total_len + `CRC32_WIDTH;

        // Serialize into AXI words
        num_beats = (pkt_len + BYTES - 1)/BYTES;
        for (i=0; i<num_beats; i++) begin
            automatic logic [DATA_WIDTH-1:0] tdata;
            automatic logic [DATA_WIDTH/8-1:0] tkeep;
            tdata = '0;
            tkeep = '0;
            for (j=0; j<BYTES; j++) begin
                automatic int idx = i*BYTES + j;
                if (idx < pkt_len)
                begin
                    tdata[8*(j) +: 8] = bytes[idx];
                    tkeep[j] = 1'b1;
                end
                else
                    tdata[8*(j) +: 8] = 8'h00;
            end
            send_word(tdata, tkeep, i==num_beats-1);
        end
    endtask


    // -----------------------------
    // Main test
    initial begin
        @(posedge rst_n);
        m_axis_if.tready <= 1;
        $display("Starting packet test...");

        for (int n=0; n<`NUM_PACKETS; n++) begin
            automatic bit valid_pkt = 1;//$urandom_range(0,1);
            automatic int timeout = 1000;

            // Expected values
            automatic logic [47:0] exp_dst_mac;
            automatic logic [47:0] exp_src_mac;
            automatic logic [31:0] exp_src_ip;
            automatic logic [31:0] exp_dst_ip;
            automatic logic [7:0]  exp_protocol;
            automatic logic [15:0] exp_total_length;
            automatic logic [15:0] exp_pseudo_header;
            automatic logic        exp_crc32_ok;
            automatic bit expected_checksum_ok;
            automatic bit expected_ethertype_ok = 1'b1;
            automatic bit expected_length_ok   = 1'b1;
            automatic bit pass;
            automatic bit payload_pass = 1; // assume success

            meta_ready <= 0;

            send_packet(valid_pkt, exp_dst_mac, exp_src_mac, exp_src_ip, exp_dst_ip, exp_protocol, exp_total_length, exp_pseudo_header, exp_crc32_ok);

            while(!(meta_crc32_valid && meta_valid)) @(posedge clk);

            expected_checksum_ok = valid_pkt;
            
            if(expected_payload.size() != rx_buffer.size())
            begin
                payload_pass = 0;
                $display("ERROR: expected array size is %0d but we got %0d", expected_payload.size(), rx_buffer.size());
            end
            else
            begin
                // Compare payload byte-by-byte
                for (int it = 0; it < payload_len; it++) begin
                    if (expected_payload[it] !== rx_buffer[it]) begin
                        payload_pass = 0;
                        $display("Payload mismatch at byte %0d: expected %h, got %h", it, expected_payload[it], rx_buffer[it]);
                    end
                end
            end

            // Combine metadata and payload pass
            pass = (meta_checksum_ok == expected_checksum_ok) &&
                                (meta_ethertype_ok == expected_ethertype_ok) &&
                                (meta_length_ok   == expected_length_ok) &&
                                (meta_dst_mac     == exp_dst_mac) &&
                                (meta_src_mac     == exp_src_mac) &&
                                (meta_src_ip      == exp_src_ip) &&
                                (meta_dst_ip      == exp_dst_ip) &&
                                (meta_protocol    == exp_protocol) &&
                                (meta_total_length== exp_total_length) &&
                                (meta_crc32       == exp_crc32_ok) &&
                                (meta_pseudo_header == exp_pseudo_header) &&
                                payload_pass;

            if (pass)
                $display("[%0t] PASS: Packet correctly extracted and payload matches (valid=%0b)", $time, valid_pkt);
            else begin
                $display("[%0t] FAIL: Packet check failed (valid=%0b)", $time, valid_pkt);
                if (!payload_pass) $display("    Payload did not match expected data.");
                $display("    Expected metadata: checksum=%0b, ethertype=%0b, length=%0b, dst_mac=%h, src_mac=%h, src_ip=%h, dst_ip=%h, proto=%h, total_len=%0d, crc=%h, tcp_pseudo_header=%h",
                        expected_checksum_ok, expected_ethertype_ok, expected_length_ok,
                        exp_dst_mac, exp_src_mac, exp_src_ip, exp_dst_ip, exp_protocol, exp_total_length, exp_crc32_ok, exp_pseudo_header);
                $display("    Actual   metadata: checksum=%0b, ethertype=%0b, length=%0b, dst_mac=%h, src_mac=%h, src_ip=%h, dst_ip=%h, proto=%h, total_len=%0d, crc=%h, tcp_pseudo_header=%h",
                        meta_checksum_ok, meta_ethertype_ok, meta_length_ok,
                        meta_dst_mac, meta_src_mac, meta_src_ip, meta_dst_ip, meta_protocol, meta_total_length, meta_crc32, meta_pseudo_header);
            end
            
            //acknowledge the data
            meta_ready <= 1;
            while(meta_valid) @(posedge clk);


            expected_payload = {};
            rx_buffer = {};

        end

        $display("Packet test complete.");
        $stop(0);
    end

endmodule