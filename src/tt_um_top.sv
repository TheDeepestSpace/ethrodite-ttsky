`timescale 1ns / 1ps
// `include "uart_axi_bridge.sv"
// `include "uart_top.sv"

module tt_um_top (
    input  wire [7:0] ui_in,    // Dedicated inputs
    output wire [7:0] uo_out,   // Dedicated outputs
    input  wire [7:0] uio_in,   // IOs: Input path
    output wire [7:0] uio_out,  // IOs: Output path
    output wire [7:0] uio_oe,   // IOs: Enable path (active high: 0=input, 1=output)
    input  wire       ena,      // always 1 when the design is powered, so you can ignore it
    input  wire       clk,      // clock
    input  wire       rst_n     // reset_n - low to reset
);

  // All output pins must be assigned. If not used, assign to 0.
  assign uo_out  = ui_in + uio_in;  // Example: ou_out is the sum of ui_in and uio_in
  assign uio_out = 0;
  assign uio_oe  = 0;

  // List all unused inputs to prevent warnings
  wire _unused = &{ena, clk, rst_n, 1'b0};

  tt_um_tcp_top um_tcp_top (
      .clk(clk),
      .rst_n(rst_n),
      .ena(ena)
      , .uart_rx(uio_in[0]),
      .uart_tx(uio_out[0])
  );

endmodule

module tt_um_tcp_top #(
    parameter int DATA_WIDTH = 8,
    parameter int BAUD_RATE  = 115200,
    parameter int CLK_FREQ   = 50000000
) (
    input logic clk,
    input logic rst_n,

    input wire ena,

    // TinyTapeout UART pins
    input  logic uart_rx,
    output logic uart_tx
);

  wire _unused = ena;

  // -------------------------------
  // Internal AXI Stream connections
  // -------------------------------
  axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) uart_in_if ();
  axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) uart_out_if ();

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
      .CLK_BITS  (CALC_CLK_BITS)  // 4. Pass 9 to the module
  ) u_uart_bridge (
      .clk  (clk),
      .rst_n(rst_n),

      // AXI stream connections
      .uart_in (uart_in_if),
      .uart_out(uart_out_if),

      // Physical UART pins
      .uart_tx(uart_tx),
      .uart_rx(uart_rx),

      // Bit timing
      .clk_per_bit(clk_per_bit)  // 5. Connect the 9-bit wire
  );

  // -------------------------------
  // Core UART + TCP system
  // -------------------------------
  uart_top #(
      .DATA_WIDTH(DATA_WIDTH),
      .BAUD_RATE (BAUD_RATE),
      .CLK_FREQ  (CLK_FREQ)
  ) u_uart_top (
      .clk  (clk),
      .rst_n(rst_n),

      // AXI-stream UART side
      .uart_out(uart_in_if),
      .uart_in (uart_out_if)
  );

endmodule
