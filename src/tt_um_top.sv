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

  // List all unused inputs to prevent warnings
// Tie all unused outputs to 0
  assign uo_out   = 8'b0;          // nothing on dedicated outputs
  assign uio_out[7:1]  = '0; // only bit 0 is used by UART
  assign uio_oe   = 8'b0;          // nothing else enabled

  // Tie unused inputs to a dummy wire to avoid warnings
  wire _unused = &{ui_in, uio_in[7:1], ena, clk, rst_n};

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
  // Internal AXI Stream signals
  // -------------------------------
  logic [DATA_WIDTH-1:0] uart_in_tdata;
  logic                  uart_in_tvalid;
  logic                  uart_in_tready;
  logic                  uart_in_tlast;
  
  logic [DATA_WIDTH-1:0] uart_out_tdata;
  logic                  uart_out_tvalid;
  logic                  uart_out_tready;
  logic                  uart_out_tlast;

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
      .uart_in_tdata (uart_in_tdata),
      .uart_in_tvalid(uart_in_tvalid),
      .uart_in_tready(uart_in_tready),
      .uart_in_tlast (uart_in_tlast),
      .uart_out_tdata (uart_out_tdata),
      .uart_out_tvalid(uart_out_tvalid),
      .uart_out_tready(uart_out_tready),
      .uart_out_tlast (uart_out_tlast),

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

      // AXI-stream UART side (note: swapped from bridge perspective)
      .uart_in_tdata (uart_out_tdata),
      .uart_in_tvalid(uart_out_tvalid),
      .uart_in_tready(uart_out_tready),
      .uart_in_tlast (uart_out_tlast),
      .uart_out_tdata (uart_in_tdata),
      .uart_out_tvalid(uart_in_tvalid),
      .uart_out_tready(uart_in_tready),
      .uart_out_tlast (uart_in_tlast)
  );

endmodule
