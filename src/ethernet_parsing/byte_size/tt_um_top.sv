`timescale 1ns/1ps
`include "uart_axi_bridge.sv"
`include "uart_top.sv"

module tt_um_top #(
    parameter int DATA_WIDTH = 8,
    parameter int BAUD_RATE = 115200,
    parameter int CLK_FREQ  = 50000000
)(
    input  logic clk,
    input  logic rst_n,

    // TinyTapeout UART pins
    input  logic uart_rx,
    output logic uart_tx
);

    // -------------------------------
    // Internal AXI Stream connections
    // -------------------------------
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) uart_in_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) uart_out_if();

    // -------------------------------
    // UART bridge (connects pins <-> AXI)
    // -------------------------------
    
    // --- FIX IS HERE ---
    // 1. Calculate the value (434)
    localparam int CLK_PER_BIT_VAL = (CLK_FREQ / BAUD_RATE);

    // 2. Calculate the bits needed (9)
    localparam int CALC_CLK_BITS = $clog2(CLK_PER_BIT_VAL);

    // 3. Declare the wire with the correct 9-bit width
    logic [CALC_CLK_BITS-1:0] clk_per_bit;
    assign clk_per_bit = CLK_PER_BIT_VAL;
    // --- END FIX ---

    uart_axi_bridge #(
        .DATA_WIDTH(DATA_WIDTH),
        .CLK_BITS(CALC_CLK_BITS) // 4. Pass 9 to the module
    ) u_uart_bridge (
        .clk(clk),
        .rst_n(rst_n),

        // AXI stream connections
        .uart_in(uart_in_if),
        .uart_out(uart_out_if),

        // Physical UART pins
        .uart_tx(uart_tx),
        .uart_rx(uart_rx),

        // Bit timing
        .clk_per_bit(clk_per_bit) // 5. Connect the 9-bit wire
    );

    // -------------------------------
    // Core UART + TCP system
    // -------------------------------
    uart_top #(
        .DATA_WIDTH(DATA_WIDTH),
        .BAUD_RATE(BAUD_RATE),
        .CLK_FREQ(CLK_FREQ)
    ) u_uart_top (
        .clk(clk),
        .rst_n(rst_n),

        // AXI-stream UART side
        .uart_out(uart_in_if),
        .uart_in(uart_out_if)
    );

endmodule