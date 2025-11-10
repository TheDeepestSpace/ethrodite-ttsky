`timescale 1ns/1ps
`include "axi_stream_if.sv" // Assuming this is available
// `include "ethernet_info.svh" // Assuming this is available

module tcp_reorder_buffer #(
    parameter int DATA_WIDTH = 8, // Per your comment, 8-bit data
    parameter int DEPTH      = 64, // Total bytes in buffer
    parameter int SEQ_BITS   = 32
)(
    input  logic clk,
    input  logic rst_n,

    // Incoming AXI4-Stream (from TCP RX engine)
    axi_stream_if.slave s_axis,

    // Outgoing AXI4-Stream (to upper layer)
    axi_stream_if.master m_axis,

    // Sequence tracking
    input  logic [SEQ_BITS-1:0] seq_base,   // starting seq# of the base (anchor)
    input  logic                base_valid, // pulse when seq_base is valid
    input  logic [SEQ_BITS-1:0] seq_start,  // starting seq# (byte address) of current incoming beat

    output logic [31:0]         window_size, // remaining byte space
    output logic [31:0]         ack_out,
    output logic                ack_done
);

    // ---------- parameters /locals ----------
    localparam int PACKET_DEPTH = DEPTH; // 1024 slots
    localparam int ADDR_BITS    = $clog2(PACKET_DEPTH); // 10 bits
    localparam int VALID_BIT_IDX = 0;
    localparam int DATA_LSB_IDX  = 1;
    localparam int DATA_MSB_IDX  = DATA_LSB_IDX + DATA_WIDTH - 1; // 8

    // ---------- memory (ASIC-friendly 1RW1R) ----------
    // This will be one dual-port SRAM macro.
    logic [15:0] combined_mem [0:PACKET_DEPTH-1];

    // ---------- control regs ----------
    logic [SEQ_BITS-1:0] base_seq_reg;
    logic                base_defined;
    logic [31:0]         used_bytes;
    logic [SEQ_BITS-1:0] prev_seq;
    logic [SEQ_BITS-1:0] expected_seq_reg;
    logic [ADDR_BITS-1:0] write_addr;
    logic [ADDR_BITS-1:0] read_raddr; // Addr of slot we want to send
    logic [ADDR_BITS-1:0] reset_index;
    logic                 reset_done;
    logic [15:0]          read_data_reg; // Holds data from Port B

    typedef enum logic [0:0] {S_READ, S_SEND} state_e;
    state_e state_r;

    // ---------- Combinatorial Logic ----------
    logic s_axis_is_writing;
    logic fsm_wants_to_clear;
    logic fsm_gets_port_a;

    assign ack_out     = expected_seq_reg;
    assign window_size = DEPTH - used_bytes;

    // s_axis.tready is now independent of the output FSM,
    // because arbitration handles any Port A conflicts.
    assign s_axis.tready = base_defined && (prev_seq == seq_start);

    assign s_axis_is_writing  = s_axis.tvalid && s_axis.tready;

    always_ff @(posedge clk, negedge rst_n) begin
        if (!rst_n) begin
            write_addr       <= '0;
            prev_seq         <= '0;
            base_defined     <= 1'b0;
            reset_index      <= '0;
            reset_done       <= 1'b0;
            read_raddr       <= '0;
            expected_seq_reg <= '0;
            ack_done         <= 1'b0;
            read_data_reg    <= '0;
            m_axis.tvalid    <= 1'b0;
            m_axis.tdata     <= '0;
            state_r <= S_READ;
        end
        else begin
            // --- Default non-stalling behavior ---
            m_axis.tvalid <= 1'b0;
            ack_done      <= 1'b0;

            if (!reset_done) begin
                // --- Reset Loop ---
                // Port A logic is handled in always_comb
                reset_index <= reset_index + 1;
                if (reset_index == PACKET_DEPTH-1)
                    reset_done <= 1'b1;

            end else if (base_valid) begin
                // --- New Base Sequence ---
                base_seq_reg     <= seq_base;
                base_defined     <= 1;
                expected_seq_reg <= seq_base;
                m_axis.tvalid    <= 0;
                read_raddr       <= '0;
                ack_done         <= 0;
            end else if (seq_start != prev_seq) begin
                prev_seq   <= seq_start;
                write_addr <= (seq_start - base_seq_reg) % PACKET_DEPTH;
            end else if (s_axis_is_writing) begin
                write_addr <= (write_addr + 1) % PACKET_DEPTH;
                if (write_addr == (read_raddr+1) % PACKET_DEPTH)
                    read_data_reg <= {7'b0, s_axis.tdata, 1'b1};
                else
                    read_data_reg <= combined_mem[read_raddr+1];
                used_bytes <= used_bytes+1;
                combined_mem[write_addr] <= {7'b0, s_axis.tdata, 1'b1};
                state_r <= S_READ;
            end else if (state_r == S_READ) begin
                read_data_reg  <= combined_mem[read_raddr];
                state_r <= S_SEND;
            end
            else if (read_data_reg[VALID_BIT_IDX]) begin
                m_axis.tvalid <= 1;
                m_axis.tdata  <= read_data_reg[DATA_MSB_IDX:DATA_LSB_IDX];
                expected_seq_reg <= expected_seq_reg + 1;
                state_r <= S_READ;
                combined_mem[read_raddr] <= '0;
                read_raddr <= (read_raddr + 1) % PACKET_DEPTH;
                used_bytes <= used_bytes-1;
            end
            else begin
                ack_done <= 1;
            end
        end
    end
endmodule
