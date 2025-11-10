`timescale 1ns/1ps
`include "ethernet_info.svh"

module tcp_top(
    input  logic clk,
    input  logic rst_n,

    // AXI4-Stream slave (commands from App)
    input  logic [7:0] instruction_axis_tdata,
    input  logic       instruction_axis_tvalid,
    output logic       instruction_axis_tready,
    input  logic       instruction_axis_tlast,

    // output to rest of FPGA (reordered, to application/upper layer)
    output logic [7:0] output_axis_tdata,
    output logic       output_axis_tvalid,
    input  logic       output_axis_tready,
    output logic       output_axis_tlast,

    // output to PHY (frames to be transmitted)
    output logic [7:0] phy_axis_tdata,
    output logic       phy_axis_tvalid,
    input  logic       phy_axis_tready,
    output logic       phy_axis_tlast,

    // AXI4-Stream master (to App - notifications / responses)
    output logic [7:0] response_axis_tdata,
    output logic       response_axis_tvalid,
    input  logic       response_axis_tready,
    output logic       response_axis_tlast,

    // AXI4-Stream slave (incoming payload from PHY)
    input  logic [7:0] s_payload_axis_tdata,
    input  logic       s_payload_axis_tvalid,
    output logic       s_payload_axis_tready,
    input  logic       s_payload_axis_tlast,

    // AXI4-Stream slave (outgoing payload from App to be sent)
    input  logic [7:0] s_app_axis_tdata,
    input  logic       s_app_axis_tvalid,
    output logic       s_app_axis_tready,
    input  logic       s_app_axis_tlast,

    // Connection info (latched on instruction) - flattened for Yosys compatibility
    input  logic [47:0] in_info_src_mac,
    input  logic [47:0] in_info_dst_mac,
    input  logic [31:0] in_info_src_ip,
    input  logic [31:0] in_info_dst_ip,
    input  logic [15:0] in_info_src_port,
    input  logic [15:0] in_info_dst_port,
    input  logic [15:0] in_info_payload_len,
    input  logic [15:0] in_info_tcp_checksum
);

    // -----------------
    // Internal signals (interconnect between submodules)
    // -----------------
    // ethernet -> tcp_handler
    logic [7:0] tcp_payload_tdata;
    logic       tcp_payload_tvalid;
    logic       tcp_payload_tready;
    logic       tcp_payload_tlast;
    
    // tcp_handler -> reorder buffer
    logic [7:0] final_payload_tdata;
    logic       final_payload_tvalid;
    logic       final_payload_tready;
    logic       final_payload_tlast;

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
        .instruction_axis_tdata (instruction_axis_tdata),
        .instruction_axis_tvalid(instruction_axis_tvalid),
        .instruction_axis_tready(instruction_axis_tready),
        .instruction_axis_tlast (instruction_axis_tlast),
        .response_axis_tdata    (response_axis_tdata),
        .response_axis_tvalid   (response_axis_tvalid),
        .response_axis_tready   (response_axis_tready),
        .response_axis_tlast    (response_axis_tlast),
        .sender_start       (sender_start),
        .sender_info        (sender_info),
        .sender_busy        (sender_busy),
        .in_info_src_mac    (in_info_src_mac),
        .in_info_dst_mac    (in_info_dst_mac),
        .in_info_src_ip     (in_info_src_ip),
        .in_info_dst_ip     (in_info_dst_ip),
        .in_info_src_port   (in_info_src_port),
        .in_info_dst_port   (in_info_dst_port),
        .in_info_payload_len(in_info_payload_len),
        .in_info_tcp_checksum(in_info_tcp_checksum),
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
        .s_axis_tdata      (s_payload_axis_tdata),
        .s_axis_tvalid     (s_payload_axis_tvalid),
        .s_axis_tready     (s_payload_axis_tready),
        .s_axis_tlast      (s_payload_axis_tlast),
        .m_axis_tdata      (tcp_payload_tdata),
        .m_axis_tvalid     (tcp_payload_tvalid),
        .m_axis_tready     (tcp_payload_tready),
        .m_axis_tlast      (tcp_payload_tlast),
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
        .s_axis_tdata       (tcp_payload_tdata),
        .s_axis_tvalid      (tcp_payload_tvalid),
        .s_axis_tready      (tcp_payload_tready),
        .s_axis_tlast       (tcp_payload_tlast),
        .m_axis_tdata       (final_payload_tdata),
        .m_axis_tvalid      (final_payload_tvalid),
        .m_axis_tready      (final_payload_tready),
        .m_axis_tlast       (final_payload_tlast),
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
        .s_axis_tdata (s_app_axis_tdata),
        .s_axis_tvalid(s_app_axis_tvalid),
        .s_axis_tready(s_app_axis_tready),
        .s_axis_tlast (s_app_axis_tlast),
        .m_axis_tdata (phy_axis_tdata),
        .m_axis_tvalid(phy_axis_tvalid),
        .m_axis_tready(phy_axis_tready),
        .m_axis_tlast (phy_axis_tlast),
        .busy  (sender_busy)
    );

    // Reorder buffer (deliver in-order bytes to upper layer)
    tcp_reorder_buffer u_reorder (
        .clk        (clk),
        .rst_n      (rst_n),
        .s_axis_tdata (final_payload_tdata),
        .s_axis_tvalid(final_payload_tvalid),
        .s_axis_tready(final_payload_tready),
        .s_axis_tlast (final_payload_tlast),
        .m_axis_tdata (output_axis_tdata),
        .m_axis_tvalid(output_axis_tvalid),
        .m_axis_tready(output_axis_tready),
        .m_axis_tlast (output_axis_tlast),
        .seq_base   (seq_base),
        .base_valid (base_valid),
        .seq_start  (seq_start),
        .window_size(window_size),
        .ack_out(expected_ack),
        .ack_done(ack_done)
    );

endmodule
