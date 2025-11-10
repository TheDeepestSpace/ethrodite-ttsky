`timescale 1ns/1ps
`include "ethernet_info.svh"

module tcp_handler #(
    parameter int DATA_WIDTH  = `INPUTWIDTH
)(
    input  logic clk,
    input  logic rst_n,

    // AXI4-Stream slave
    input  logic [DATA_WIDTH-1:0] s_axis_tdata,
    input  logic                  s_axis_tvalid,
    output logic                  s_axis_tready,
    input  logic                  s_axis_tlast,

    // AXI4-Stream master (forwarded payload)
    output logic [DATA_WIDTH-1:0] m_axis_tdata,
    output logic                  m_axis_tvalid,
    input  logic                  m_axis_tready,
    output logic                  m_axis_tlast,

    // Metadata outputs
    output logic       meta_valid,
    input  logic       meta_ready,
    output logic [15:0] meta_src_port,
    output logic [15:0] meta_dst_port,
    output logic [31:0] meta_seq_num,
    output logic [31:0] meta_ack_num,
    output logic [7:0]  meta_flags,
    output logic [15:0] meta_window_size,
    output logic [15:0] meta_payload_len
);

    localparam S_HEADER  = 2'd0;
    localparam S_FORWARD = 2'd1;
    localparam S_WAIT    = 2'd2;
    logic [1:0] state_r, state_n;

    // Header registers
    logic [15:0] byte_offset_r, byte_offset_n;
    logic [15:0] dst_port_r, dst_port_n;
    logic [15:0] src_port_r, src_port_n;
    logic [3:0] header_length_r, header_length_n;
    logic [5:0] flags_r, flags_n;
    logic [31:0] seq_num_r, seq_num_n;
    logic [31:0] ack_num_r, ack_num_n;
    logic [15:0] window_size_r, window_size_n;
    logic [15:0] urgent_r, urgent_n;

    // Checksum
    logic        odd_byte_valid_r, odd_byte_valid_n;
    logic [7:0]  odd_byte_r, odd_byte_n;
    logic [7:0]  header_bytes_needed_r, header_bytes_needed_n;
    logic [7:0]  header_bytes_accum_r, header_bytes_accum_n;

    // Forwarded bytes counter
    logic [31:0] forwarded_bytes_r, forwarded_bytes_n;

    // -----------------------------------------------------------------
    // AXI4 forwarding
    logic [DATA_WIDTH-1:0] m_axis_data_n;
    logic m_axis_last_n, m_axis_valid_n;
    assign s_axis_tready = 1; //add a fifo here
    //assign m_axis_tlast  = s_axis_tlast;

    // we need this as soon as we get it, so it is assigned like this
    assign meta_seq_num = seq_num_n;

    // -----------------------------------------------------------------
    // Combinational next-state
    always_comb begin
        // Defaults
        state_n                = state_r;
        byte_offset_n          = byte_offset_r;
        dst_port_n             = dst_port_r;
        src_port_n             = src_port_r;
        header_length_n        = header_length_r;
        flags_n                = flags_r;
        seq_num_n              = seq_num_r;
        ack_num_n              = ack_num_r;
        window_size_n          = window_size_r;
        urgent_n               = urgent_r;
        odd_byte_valid_n       = odd_byte_valid_r;
        odd_byte_n             = odd_byte_r;
        header_bytes_needed_n  = header_bytes_needed_r;
        header_bytes_accum_n   = header_bytes_accum_r;
        forwarded_bytes_n      = forwarded_bytes_r;
        m_axis_data_n          = s_axis_tdata;
        m_axis_last_n          = s_axis_tlast;
        m_axis_valid_n         = 0;
        if (s_axis_tvalid) begin
            // --- same case statement / header accumulation / checksum ---
            case (byte_offset_r)
                (`TCP_SRC_PORT_BASE + 0): src_port_n[15:8] = s_axis_tdata;
                (`TCP_SRC_PORT_BASE + 1): src_port_n[7:0]  = s_axis_tdata;
                (`TCP_DST_PORT_BASE + 0): dst_port_n[15:8] = s_axis_tdata;
                (`TCP_DST_PORT_BASE + 1): dst_port_n[7:0]  = s_axis_tdata;
                (`TCP_SEQ_NUM_BASE + 0): seq_num_n[31:24]  = s_axis_tdata;
                (`TCP_SEQ_NUM_BASE + 1): seq_num_n[23:16]  = s_axis_tdata;
                (`TCP_SEQ_NUM_BASE + 2): seq_num_n[15:8]   = s_axis_tdata;
                (`TCP_SEQ_NUM_BASE + 3): seq_num_n[7:0]    = s_axis_tdata;
                (`TCP_ACK_NUM_BASE + 0): ack_num_n[31:24]  = s_axis_tdata;
                (`TCP_ACK_NUM_BASE + 1): ack_num_n[23:16]  = s_axis_tdata;
                (`TCP_ACK_NUM_BASE + 2): ack_num_n[15:8]   = s_axis_tdata;
                (`TCP_ACK_NUM_BASE + 3): ack_num_n[7:0]    = s_axis_tdata;
                (`TCP_DATA_OFFSET_BASE): header_bytes_needed_n = s_axis_tdata[7:4]*4;
                (`TCP_FLAGS_BASE): flags_n = s_axis_tdata;
                (`TCP_WINDOW_SIZE_BASE + 0): window_size_n[15:8] = s_axis_tdata;
                (`TCP_WINDOW_SIZE_BASE + 1): window_size_n[7:0]  = s_axis_tdata;
                (`TCP_URGENT_PTR_BASE + 0): urgent_n[15:8] = s_axis_tdata;
                (`TCP_URGENT_PTR_BASE + 1): urgent_n[7:0]  = s_axis_tdata;
                default: ;
            endcase

            // Accumulate header bytes
            header_bytes_accum_n = header_bytes_accum_n + 1;
            byte_offset_n = byte_offset_r + 1;
            // State transitions
            case (state_r)
                S_HEADER: begin
                    if (header_bytes_accum_n >= header_bytes_needed_n && header_bytes_needed_n != 0) begin
                        // Move to forward state
                        state_n = (s_axis_tlast) ? S_WAIT : S_FORWARD;
                    end
                end
                S_FORWARD: begin
                    // Default tkeep = all bytes valid
                    forwarded_bytes_n = forwarded_bytes_n + 1;
                    m_axis_valid_n         = 1;

                    if (s_axis_tlast && s_axis_tvalid) begin
                        state_n = S_WAIT;
                        m_axis_last_n = 1;
                    end

                end
                default: ;
            endcase
        end
    end

    // -----------------------------------------------------------------
    // Sequential updates
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n || state_r == S_WAIT && meta_ready) begin
            state_r <= S_HEADER;
            byte_offset_r <= 0;
            dst_port_r <= 0;
            src_port_r <= 0;
            header_length_r <= 0;
            seq_num_r <= 0;
            ack_num_r <= 0;
            flags_r <= 0;
            window_size_r <= 0;
            odd_byte_valid_r <= 0;
            odd_byte_r <= 0;
            header_bytes_needed_r <= 0;
            header_bytes_accum_r <= 0;
            forwarded_bytes_r <= 0;
            urgent_r <= 0;
            meta_dst_port <= 0;
            meta_src_port <= 0;
            meta_ack_num <= 0;
            meta_flags <= 0;
            meta_payload_len <= 0;
            meta_window_size <= 0;

            // Also clear meta registers if needed
            meta_valid <= 0;
        end else begin
            // Latch state
            state_r             <= state_n;
            byte_offset_r       <= byte_offset_n;
            dst_port_r           <= dst_port_n; src_port_r <= src_port_n;
            header_length_r <= header_length_n; urgent_r <= urgent_n;
            odd_byte_valid_r <= odd_byte_valid_n; odd_byte_r <= odd_byte_n;
            header_bytes_needed_r <= header_bytes_needed_n; header_bytes_accum_r <= header_bytes_accum_n;
            seq_num_r <= seq_num_n; ack_num_r <= ack_num_n; flags_r <= flags_n; window_size_r <= window_size_n;
            forwarded_bytes_r <= forwarded_bytes_n;

            m_axis_tdata <= m_axis_data_n;
            m_axis_tvalid <= m_axis_valid_n;
            m_axis_tlast  <= m_axis_last_n;

            // ---------------------------
            // Metadata latching
            // Once header is complete, latch metadata from _n and keep valid high during forwarding
            if (state_n == S_FORWARD && state_r == S_HEADER) begin
                meta_dst_port      <= dst_port_n;
                meta_src_port      <= src_port_n;
                meta_ack_num       <= ack_num_n;
                meta_flags         <= flags_n;
                meta_window_size   <= window_size_n;
            end
            else if (s_axis_tlast && s_axis_tvalid) begin
                // checksum calculation
                meta_valid <= 1;
                meta_payload_len <= forwarded_bytes_n;
                meta_dst_port      <= dst_port_n;
                meta_src_port      <= src_port_n;
                meta_ack_num       <= ack_num_n;
                meta_flags         <= flags_n;
                meta_window_size   <= window_size_n;
            end
        end
    end

endmodule
