`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"
`include "tcp_sender.sv"
`include "tcp_handler.sv"
`include "tcp_brain.sv"
`include "ethernet_ipv4_handler.sv"
`include "tcp_reorder_buffer.sv"

module tcp_top(
    input  logic clk,
    input  logic rst_n,

    // AXI4-Stream slave (commands from App)
    axi_stream_if.slave instruction_axis,

    // output to rest of FPGA (reordered, to application/upper layer)
    axi_stream_if.master output_axis,

    // output to PHY (frames to be transmitted)
    axi_stream_if.master phy_axis,

    // AXI4-Stream master (to App - notifications / responses)
    axi_stream_if.master response_axis,

    // AXI4-Stream slave (incoming payload from PHY)
    axi_stream_if.slave s_payload_axis,

    // AXI4-Stream slave (outgoing payload from App to be sent)
    axi_stream_if.slave s_app_axis,

    // Connection info (latched on instruction)
    input  tcp_command_info     in_info
);

    // -----------------
    // Internal interfaces (interconnect between submodules)
    // -----------------
    axi_stream_if tcp_payload_if(); // ethernet -> tcp_handler
    axi_stream_if final_payload_if(); // tcp_handler -> reorder buffer

    // -----------------
    // Control / metadata signals
    // -----------------
    logic                 sender_start;
    tcp_packet_info_s     sender_info; // type defined in tcp_sender.sv
    logic                 sender_busy;

    // window/sequence tracking (from tcp_brain)
    logic [31:0]          window_size;
    logic [31:0]          expected_ack;
    logic [31:0]          seq_base;
    logic                 base_valid;
    logic                 ack_done;

    // Metadata produced by tcp_handler and consumed by tcp_brain
    logic                 tcp_meta_valid;
    logic                 tcp_meta_ready;
    logic [15:0]          tcp_meta_src_port;
    logic [15:0]          tcp_meta_dst_port;
    logic [31:0]          tcp_meta_seq_num;
    logic [31:0]          tcp_meta_ack_num;
    logic [7:0]           tcp_meta_flags;
    logic [15:0]          tcp_meta_window_size;
    logic [15:0]          tcp_meta_payload_len;
    logic                 tcp_meta_checksum_ok;
    logic                 tcp_meta_checksum_valid;

    // Ethernet-level metadata (from ethernet_ipv4_handler)
    logic                 eth_meta_valid;
    logic                 eth_meta_crc32_valid;
    logic                 eth_meta_ready; // driven by tcp_brain
    logic [15:0]          eth_meta_pseudo_header;
    logic [47:0]          eth_meta_dst_mac;
    logic [47:0]          eth_meta_src_mac;
    logic [31:0]          eth_meta_src_ip;
    logic [31:0]          eth_meta_dst_ip;
    logic [7:0]           eth_meta_protocol;
    logic [15:0]          eth_meta_total_length;
    logic                 eth_meta_crc32_ok;
    logic                 eth_meta_checksum_ok;
    logic                 eth_meta_ethertype_ok;
    logic                 eth_meta_length_ok;
    logic                 final_valid;

    // For reorder buffer: seq_start is the starting byte address of current incoming segment
    // We'll use the TCP handler's meta_seq_num as seq_start (latched/valid when tcp_meta_valid)
    logic [31:0]          seq_start;

    // Drive seq_start from tcp handler metadata (simple heuristic)
    assign seq_start = tcp_meta_seq_num;

    assign final_valid = tcp_meta_valid&eth_meta_valid;

    // -----------------
    // Submodule instantiations (named port mapping)
    // -----------------
    tcp_brain u_tcp_brain (
        .clk             (clk),
        .rst_n           (rst_n),
        .instruction_axis(instruction_axis),
        .response_axis   (response_axis),
        .sender_start    (sender_start),
        .sender_info     (sender_info),
        .sender_busy     (sender_busy),
        .in_info         (in_info),
        .window_size     (window_size),
        .expected_ack    (expected_ack),
        .ack_done        (ack_done),
        .seq_base        (seq_base),
        .base_valid      (base_valid),
        .meta_valid      (final_valid),
        .meta_ready      (tcp_meta_ready),
        .meta_seq_num    (tcp_meta_seq_num),
        .meta_ack_num    (tcp_meta_ack_num),
        .meta_flags      (tcp_meta_flags),
        .meta_window_size(tcp_meta_window_size),
        .meta_payload_len(tcp_meta_payload_len)
    );

    // Ethernet / IPv4 parser
    ethernet_ipv4_handler u_eth_ipv4 (
        .clk               (clk),
        .rst_n             (rst_n),
        .s_axis            (s_payload_axis),
        .m_axis            (tcp_payload_if),
        .meta_valid        (eth_meta_valid),
        .meta_ready        (tcp_meta_ready),     // backpressure from brain
        .meta_dst_mac      (eth_meta_dst_mac),
        .meta_src_mac      (eth_meta_src_mac),
        .meta_src_ip       (eth_meta_src_ip),
        .meta_dst_ip       (eth_meta_dst_ip),
        .meta_protocol     (eth_meta_protocol),
        .meta_total_length (eth_meta_total_length),
        .meta_ethertype_ok (eth_meta_ethertype_ok)
    );

    // TCP header parser / forwarder
    tcp_handler u_tcp_handler (
        .clk                (clk),
        .rst_n              (rst_n),
        .s_axis             (tcp_payload_if),
        .m_axis             (final_payload_if),
        .meta_valid         (tcp_meta_valid),
        .meta_ready         (tcp_meta_ready),
        .meta_src_port      (tcp_meta_src_port),
        .meta_dst_port      (tcp_meta_dst_port),
        .meta_seq_num       (tcp_meta_seq_num),
        .meta_ack_num       (tcp_meta_ack_num),
        .meta_flags         (tcp_meta_flags),
        .meta_window_size   (tcp_meta_window_size),
        .meta_payload_len   (tcp_meta_payload_len)
    );

    // TCP sender (transmit engine)
    tcp_sender u_tcp_sender (
        .clk   (clk),
        .rst_n (rst_n),
        .start (sender_start),
        .i_pkt (sender_info),
        .s_axis(s_app_axis),   // payload source from application
        .m_axis(phy_axis),     // output to PHY
        .busy  (sender_busy)
    );

    // Reorder buffer (deliver in-order bytes to upper layer)
    tcp_reorder_buffer u_reorder (
        .clk        (clk),
        .rst_n      (rst_n),
        .s_axis     (final_payload_if),
        .m_axis     (output_axis),
        .seq_base   (seq_base),
        .base_valid (base_valid),
        .seq_start  (seq_start),
        .window_size(window_size),
        .ack_out(expected_ack),
        .ack_done(ack_done)
    );

endmodule
