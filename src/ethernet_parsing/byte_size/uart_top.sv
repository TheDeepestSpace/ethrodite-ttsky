`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"
`include "tcp_top.sv"
`include "uart_core.sv"
`include "uart_tcp_mux.sv"

module uart_top #(
    parameter int DATA_WIDTH = 64,
    parameter int BAUD_RATE = 115200,
    parameter int CLK_FREQ = 50000000
)(
    input  logic clk,
    input  logic rst_n,

    // UART physical interface (only external pins needed for chip)
    input  logic uart_rx,
    output logic uart_tx,

    // Debug/status outputs (optional)
    output logic [7:0] debug_status,
    output logic connection_active
);

    // Internal AXI Stream interfaces between UART mux and TCP stack
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) instruction_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) response_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) output_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) phy_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) payload_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) app_data_if();

    // TCP connection info - could be configured via UART commands
    // For now, using default values
    tcp_command_info conn_info;

    // Initialize connection info with default values
    initial begin
        conn_info.src_mac = 48'hAABBCCDDEEFF;
        conn_info.dst_mac = 48'h112233445566;
        conn_info.src_ip = 32'h0A000001;      // 10.0.0.1
        conn_info.dst_ip = 32'h0A000002;      // 10.0.0.2
        conn_info.src_port = 16'd1234;
        conn_info.dst_port = 16'd80;
        conn_info.payload_len = 16'h0;
        conn_info.tcp_checksum = 16'h0;
    end

    // UART Multiplexer - handles UART ↔ AXI Stream conversion
    uart_tcp_mux #(
        .DATA_WIDTH(DATA_WIDTH)
    ) u_uart_mux (
        .clk(clk),
        .rst_n(rst_n),
        .uart_rx(uart_rx),
        .uart_tx(uart_tx),
        // Connect to TCP stack interfaces
        .app_instruction_axis(instruction_if.master),
        .app_response_axis(response_if.slave),
        .eth_payload_axis(payload_if.master),
        .eth_phy_axis(phy_if.slave)
    );

    // Your existing TCP stack
    tcp_top u_tcp_top (
        .clk(clk),
        .rst_n(rst_n),
        // Application command interface
        .instruction_axis(instruction_if.slave),
        .response_axis(response_if.master),
        // Ethernet PHY interface (now via UART)
        .phy_axis(phy_if.master),           // TX frames to UART
        .s_payload_axis(payload_if.slave),  // RX frames from UART
        // Application data interface
        .output_axis(output_if.master),     // Processed TCP data
        .s_app_axis(app_data_if.slave),     // App data to send
        // Connection configuration
        .in_info(conn_info)
    );

    // Handle processed TCP data output
    // This could be forwarded back via UART as another packet type
    always_ff @(posedge clk) begin
        output_if.tready <= 1; // Always ready to accept processed data
        // TODO: Could buffer and send back via UART if needed
    end

    // Handle application data input
    // For now, no application data to send
    always_ff @(posedge clk) begin
        app_data_if.tvalid <= 0;
        app_data_if.tdata <= '0;
        app_data_if.tkeep <= '0;
        app_data_if.tlast <= 0;
    end

    // Debug status
    always_ff @(posedge clk) begin
        debug_status <= {
            instruction_if.tvalid,
            response_if.tvalid,
            payload_if.tvalid,
            phy_if.tvalid,
            output_if.tvalid,
            u_uart_mux.rx_state[2:0]
        };

        // Simple connection active indicator
        connection_active <= response_if.tvalid;
    end

endmodule
