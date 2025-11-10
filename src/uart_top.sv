`timescale 1ns/1ps
// `include "tcp_top.sv"
// `include "uart_tcp_mux.sv"

module uart_top #(
    parameter int DATA_WIDTH = 8,
    parameter int BAUD_RATE = 115200,
    parameter int CLK_FREQ = 50000000
)(
    input  logic clk,
    input  logic rst_n,

    // Physical UART interface - slave (input from UART)
    input  logic [DATA_WIDTH-1:0] uart_in_tdata,
    input  logic                  uart_in_tvalid,
    output logic                  uart_in_tready,
    input  logic                  uart_in_tlast,
    
    // Physical UART interface - master (output to UART)
    output logic [DATA_WIDTH-1:0] uart_out_tdata,
    output logic                  uart_out_tvalid,
    input  logic                  uart_out_tready,
    output logic                  uart_out_tlast
);

    // -------------------------------
    // Internal AXI Stream signals
    // -------------------------------
    // instruction interface (mux -> brain)
    logic [DATA_WIDTH-1:0] instruction_tdata;
    logic                  instruction_tvalid;
    logic                  instruction_tready;
    logic                  instruction_tlast;
    
    // response interface (brain -> mux)
    logic [DATA_WIDTH-1:0] response_tdata;
    logic                  response_tvalid;
    logic                  response_tready;
    logic                  response_tlast;
    
    // output interface (tcp -> mux)
    logic [DATA_WIDTH-1:0] output_tdata;
    logic                  output_tvalid;
    logic                  output_tready;
    logic                  output_tlast;
    
    // phy interface (tcp -> mux)
    logic [DATA_WIDTH-1:0] phy_tdata;
    logic                  phy_tvalid;
    logic                  phy_tready;
    logic                  phy_tlast;
    
    // payload interface (mux -> tcp)
    logic [DATA_WIDTH-1:0] payload_tdata;
    logic                  payload_tvalid;
    logic                  payload_tready;
    logic                  payload_tlast;
    
    // app_data interface (mux -> tcp)
    logic [DATA_WIDTH-1:0] app_data_tdata;
    logic                  app_data_tvalid;
    logic                  app_data_tready;
    logic                  app_data_tlast;

    // TCP connection info (configured via UART commands)
    tcp_command_info conn_info;

    // -------------------------------
    // TCP stack instantiation
    // -------------------------------
    tcp_top u_tcp_top (
        .clk(clk),
        .rst_n(rst_n),
        .instruction_axis_tdata (instruction_tdata),
        .instruction_axis_tvalid(instruction_tvalid),
        .instruction_axis_tready(instruction_tready),
        .instruction_axis_tlast (instruction_tlast),
        .response_axis_tdata    (response_tdata),
        .response_axis_tvalid   (response_tvalid),
        .response_axis_tready   (response_tready),
        .response_axis_tlast    (response_tlast),
        .phy_axis_tdata         (phy_tdata),
        .phy_axis_tvalid        (phy_tvalid),
        .phy_axis_tready        (phy_tready),
        .phy_axis_tlast         (phy_tlast),
        .s_payload_axis_tdata   (payload_tdata),
        .s_payload_axis_tvalid  (payload_tvalid),
        .s_payload_axis_tready  (payload_tready),
        .s_payload_axis_tlast   (payload_tlast),
        .output_axis_tdata      (output_tdata),
        .output_axis_tvalid     (output_tvalid),
        .output_axis_tready     (output_tready),
        .output_axis_tlast      (output_tlast),
        .s_app_axis_tdata       (app_data_tdata),
        .s_app_axis_tvalid      (app_data_tvalid),
        .s_app_axis_tready      (app_data_tready),
        .s_app_axis_tlast       (app_data_tlast),
        .in_info(conn_info)
    );

    // -------------------------------
    // UART-to-AXI MUX instantiation
    // -------------------------------
    uart_tcp_mux #(
        .DATA_WIDTH(DATA_WIDTH)
    ) u_uart_mux (
        .clk(clk),
        .rst_n(rst_n),

        // Physical UART input
        .uart_in_tdata (uart_in_tdata),
        .uart_in_tvalid(uart_in_tvalid),
        .uart_in_tready(uart_in_tready),
        .uart_in_tlast (uart_in_tlast),

        // UART commands driving TCP stack
        .instructions_to_brain_axis_tdata (instruction_tdata),
        .instructions_to_brain_axis_tvalid(instruction_tvalid),
        .instructions_to_brain_axis_tready(instruction_tready),
        .instructions_to_brain_axis_tlast (instruction_tlast),
        .eth_payload_axis_tdata           (payload_tdata),
        .eth_payload_axis_tvalid          (payload_tvalid),
        .eth_payload_axis_tready          (payload_tready),
        .eth_payload_axis_tlast           (payload_tlast),
        .payload_to_be_sent_axis_tdata    (app_data_tdata),
        .payload_to_be_sent_axis_tvalid   (app_data_tvalid),
        .payload_to_be_sent_axis_tready   (app_data_tready),
        .payload_to_be_sent_axis_tlast    (app_data_tlast),
        .out_info(conn_info),

        // UART output back to physical UART
        .uart_out_tdata (uart_out_tdata),
        .uart_out_tvalid(uart_out_tvalid),
        .uart_out_tready(uart_out_tready),
        .uart_out_tlast (uart_out_tlast),

        // Outputs from TCP stack going back to UART
        .rest_of_frame_axis_tdata (output_tdata),
        .rest_of_frame_axis_tvalid(output_tvalid),
        .rest_of_frame_axis_tready(output_tready),
        .rest_of_frame_axis_tlast (output_tlast),
        .eth_phy_axis_tdata       (phy_tdata),
        .eth_phy_axis_tvalid      (phy_tvalid),
        .eth_phy_axis_tready      (phy_tready),
        .eth_phy_axis_tlast       (phy_tlast),
        .app_response_axis_tdata  (response_tdata),
        .app_response_axis_tvalid (response_tvalid),
        .app_response_axis_tready (response_tready),
        .app_response_axis_tlast  (response_tlast)
    );

endmodule
