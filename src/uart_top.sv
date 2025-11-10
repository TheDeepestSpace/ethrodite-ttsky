`timescale 1ns/1ps
`include "tcp_top.sv"
`include "uart_tcp_mux.sv"

module uart_top #(
    parameter int DATA_WIDTH = 8,
    parameter int BAUD_RATE = 115200,
    parameter int CLK_FREQ = 50000000
)(
    input  logic clk,
    input  logic rst_n,

    // Physical UART interface
    axi_stream_if.slave uart_in,
    axi_stream_if.master uart_out
);

    // -------------------------------
    // Internal AXI Stream interfaces
    // -------------------------------
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) instruction_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) response_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) output_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) phy_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) payload_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) app_data_if();

    // TCP connection info (configured via UART commands)
    tcp_command_info conn_info;

    // -------------------------------
    // TCP stack instantiation
    // -------------------------------
    tcp_top u_tcp_top (
        .clk(clk),
        .rst_n(rst_n),
        .instruction_axis(instruction_if.slave),
        .response_axis(response_if.master),
        .phy_axis(phy_if.master),          // TX frames to UART mux
        .s_payload_axis(payload_if.slave), // RX frames from UART mux
        .output_axis(output_if.master),    // Processed TCP data
        .s_app_axis(app_data_if.slave),    // App data to send
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

        // Physical UART
        .uart_in(uart_in),

        // UART commands driving TCP stack
        .instructions_to_brain_axis(instruction_if.master),
        .eth_payload_axis(payload_if.master),
        .payload_to_be_sent_axis(app_data_if.master),
        .out_info(conn_info),

        // UART output back to physical UART
        .uart_out(uart_out),

        // Outputs from TCP stack going back to UART
        .rest_of_frame_axis(output_if.slave),
        .eth_phy_axis(phy_if.slave),
        .app_response_axis(response_if.slave)
    );

endmodule
