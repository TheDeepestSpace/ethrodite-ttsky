// axi_stream_fifo.sv
// AXI4-Stream FIFO (single-clock)
// Author: ChatGPT
// - Uses the provided axi_stream_if interface
// - Parameterized DATA_WIDTH, USER_WIDTH and DEPTH (power-of-two recommended)
// - Single-clock synchronous FIFO with flow-through (zero-latency) when empty
// - Accepts AXI handshakes: s_axis.tready asserted when not full; m_axis.tvalid asserted when not empty
// - Stores tdata, tkeep, tlast, tuser per-beat

`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"

module axi_stream_fifo #(
    parameter int DATA_WIDTH = `INPUTWIDTH,
    parameter int USER_WIDTH = 1,
    parameter int DEPTH = 16 // must be >=2 and ideally power of two
)(
    input  logic                 clk,
    input  logic                 rst_n,

    // upstream (producer) — connects as "slave" to this fifo
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH), .USER_WIDTH(USER_WIDTH)) .slave s_axis,

    // downstream (consumer) — connects as "master" to this fifo
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH), .USER_WIDTH(USER_WIDTH)) .master m_axis
);

    // Derived params
    localparam int KEEP_WIDTH = DATA_WIDTH/8;
    localparam int ADDR_WIDTH = $clog2(DEPTH);

    // Memory arrays
    logic [DATA_WIDTH-1:0] mem_tdata  [0:DEPTH-1];
    logic [KEEP_WIDTH-1:0] mem_tkeep  [0:DEPTH-1];
    logic                 mem_tlast  [0:DEPTH-1];
    logic [USER_WIDTH-1:0] mem_tuser  [0:DEPTH-1];

    // Pointers and counters
    logic [ADDR_WIDTH:0] wr_ptr; // extra MSB to simplify full/empty arithmetic
    logic [ADDR_WIDTH:0] rd_ptr;
    logic [ADDR_WIDTH:0] fifo_count;

    // Status
    wire empty = (fifo_count == 0);
    wire full  = (fifo_count == DEPTH);

    // Flow-through: when fifo empty we can pass s_axis beat directly to m_axis when downstream ready.
    // flow_thru active when empty and s_axis.tvalid and m_axis.tready
    wire flow_thru = empty && s_axis.tvalid && m_axis.tready;

    // Connect upstream tready: accept new beat if not full or if flow-through (downstream ready)
    // For simplicity: s_axis.tready = !full || flow_thru
    assign s_axis.tready = (!full) || flow_thru;

    // Drive downstream signals
    // When flow_thru is active, forward s_axis signals directly. Otherwise drive from memory (when not empty).
    // m_axis.tvalid when: flow_thru OR (!empty)
    assign m_axis.tvalid = flow_thru || (!empty);

    // Default outputs
    assign m_axis.tlast = flow_thru ? s_axis.tlast : mem_tlast[rd_ptr[ADDR_WIDTH-1:0]];
    assign m_axis.tdata = flow_thru ? s_axis.tdata : mem_tdata[rd_ptr[ADDR_WIDTH-1:0]];
    assign m_axis.tkeep = flow_thru ? s_axis.tkeep : mem_tkeep[rd_ptr[ADDR_WIDTH-1:0]];
    assign m_axis.tuser = flow_thru ? s_axis.tuser : mem_tuser[rd_ptr[ADDR_WIDTH-1:0]];

    // Internal handshake signals for FIFO operations
    wire write_en = s_axis.tvalid && s_axis.tready && !flow_thru; // write into memory
    wire read_en  = m_axis.tvalid && m_axis.tready && !flow_thru; // read from memory

    // Update memory on write
    always_ff @(posedge clk) begin
        if (!rst_n) begin
            wr_ptr <= '0;
        end else begin
            if (write_en) begin
                mem_tdata[wr_ptr[ADDR_WIDTH-1:0]] <= s_axis.tdata;
                mem_tkeep[wr_ptr[ADDR_WIDTH-1:0]] <= s_axis.tkeep;
                mem_tlast[wr_ptr[ADDR_WIDTH-1:0]] <= s_axis.tlast;
                mem_tuser[wr_ptr[ADDR_WIDTH-1:0]] <= s_axis.tuser;
                wr_ptr <= wr_ptr + 1;
            end
        end
    end

    // Update read pointer on read
    always_ff @(posedge clk) begin
        if (!rst_n) begin
            rd_ptr <= '0;
        end else begin
            if (read_en) begin
                rd_ptr <= rd_ptr + 1;
            end
        end
    end

    // Update count
    always_ff @(posedge clk) begin
        if (!rst_n) begin
            fifo_count <= '0;
        end else begin
            // Four cases: write && !read, !write && read, both, neither
            case ({write_en, read_en})
                2'b10: fifo_count <= fifo_count + 1;
                2'b01: fifo_count <= fifo_count - 1;
                default: fifo_count <= fifo_count; // 00 or 11 (11 leaves count unchanged)
            endcase
        end
    end

    // Optional: simple assertions
    `ifndef SYNTHESIS
    always_ff @(posedge clk) begin
        if (!rst_n) begin end else begin
            if (fifo_count > DEPTH) begin
                $error("FIFO count exceeded DEPTH");
            end
        end
    end
    `endif

endmodule

// -----------------------------
// Quick usage example (not a full testbench):
//
// axi_stream_fifo #(.DATA_WIDTH(128), .USER_WIDTH(2), .DEPTH(32)) fifo (
//     .clk(clk), .rst_n(rst_n), .s_axis(s_axis_if), .m_axis(m_axis_if)
// );
//
// Connect upstream master to fifo.s_axis (as slave modport) and downstream slave to fifo.m_axis (as master modport).
// -----------------------------
