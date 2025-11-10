`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"

module tcp_handler #(
    parameter int DATA_WIDTH  = `INPUTWIDTH,
    parameter bit KEEP_ENABLE = 1
)(
    input  logic clk,
    input  logic rst_n,

    // AXI4-Stream slave
    axi_stream_if.slave s_axis,

    // AXI4-Stream master (forwarded payload)
    axi_stream_if.master m_axis,

    //tcp pseudo header
    input logic [15:0]  meta_pseudo_header,

    // Metadata outputs
    output logic       meta_valid,
    input  logic       meta_ready, 
    output logic [15:0] meta_src_port,
    output logic [15:0] meta_dst_port,
    output logic [31:0] meta_seq_num,
    output logic [31:0] meta_ack_num,
    output logic [7:0]  meta_flags,
    output logic [15:0] meta_window_size,
    output logic [15:0] meta_payload_len,
    output logic        meta_checksum_ok,
    output logic        meta_checksum_valid
);

    localparam int BYTES = DATA_WIDTH/8;

    typedef enum logic [1:0] {S_HEADER, S_FORWARD, S_WAIT} state_e;
    state_e state_r, state_n;

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
    logic [31:0] chksum_acc_r, chksum_acc_n;
    logic        odd_byte_valid_r, odd_byte_valid_n;
    logic [7:0]  odd_byte_r, odd_byte_n;
    logic [7:0]  header_bytes_needed_r, header_bytes_needed_n;
    logic [7:0]  header_bytes_accum_r, header_bytes_accum_n;

    // Forwarded bytes counter
    logic [31:0] forwarded_bytes_r, forwarded_bytes_n;

    // -----------------------------------------------------------------
    // AXI4 forwarding
    logic [DATA_WIDTH-1:0] m_axis_data_n;
    logic [DATA_WIDTH/8-1:0] m_axis_keep_n;
    logic m_axis_last_n, m_axis_valid_n;
    //assign m_axis.tdata  = s_axis.tdata;
    //assign m_axis.tkeep  = s_axis.tkeep;
    //assign m_axis.tvalid = (state_n == S_FORWARD || state_r == S_FORWARD || m_axis.tlast) & s_axis.tvalid;
    assign m_axis.tuser  = '0;
    assign s_axis.tready = 1; //add a fifo here
    //assign m_axis.tlast  = s_axis.tlast;

    // we need this as soon as we get it, so it is assigned like this
    assign meta_seq_num = seq_num_n;

    function automatic logic [7:0] get_byte(input logic [DATA_WIDTH-1:0] word, input int bidx);
        return word[bidx*8 +: 8];
    endfunction

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
        chksum_acc_n           = (header_bytes_accum_r == 0)? meta_pseudo_header : chksum_acc_r;
        odd_byte_valid_n       = odd_byte_valid_r;
        odd_byte_n             = odd_byte_r;
        header_bytes_needed_n  = header_bytes_needed_r;
        header_bytes_accum_n   = header_bytes_accum_r;
        forwarded_bytes_n      = forwarded_bytes_r;
        m_axis_data_n          = s_axis.tdata;
        m_axis_keep_n          = s_axis.tkeep;
        m_axis_last_n          = s_axis.tlast;
        m_axis_valid_n         = 0;

        if (s_axis.tvalid) begin
            // Instead of looping 0..valid_bytes, loop over BYTES and check tkeep
            automatic int valid_idx = 0;
            for (int b = 0; b < BYTES; b++) begin
                if (!KEEP_ENABLE || s_axis.tkeep[b]) begin
                    automatic logic [7:0] curbyte = get_byte(s_axis.tdata, b);
                    automatic int pkt_offset = byte_offset_r + valid_idx; // increment only for valid bytes
                    // --- same case statement / header accumulation / checksum ---
                    case (pkt_offset)
                        (`TCP_SRC_PORT_BASE + 0): src_port_n[15:8] = curbyte;
                        (`TCP_SRC_PORT_BASE + 1): src_port_n[7:0]  = curbyte;
                        (`TCP_DST_PORT_BASE + 0): dst_port_n[15:8] = curbyte;
                        (`TCP_DST_PORT_BASE + 1): dst_port_n[7:0]  = curbyte;
                        (`TCP_SEQ_NUM_BASE + 0): seq_num_n[31:24]  = curbyte;
                        (`TCP_SEQ_NUM_BASE + 1): seq_num_n[23:16]  = curbyte;
                        (`TCP_SEQ_NUM_BASE + 2): seq_num_n[15:8]   = curbyte;
                        (`TCP_SEQ_NUM_BASE + 3): seq_num_n[7:0]    = curbyte;
                        (`TCP_ACK_NUM_BASE + 0): ack_num_n[31:24]  = curbyte;
                        (`TCP_ACK_NUM_BASE + 1): ack_num_n[23:16]  = curbyte;
                        (`TCP_ACK_NUM_BASE + 2): ack_num_n[15:8]   = curbyte;
                        (`TCP_ACK_NUM_BASE + 3): ack_num_n[7:0]    = curbyte;
                        (`TCP_DATA_OFFSET_BASE): header_bytes_needed_n = curbyte[7:4]*4;
                        (`TCP_FLAGS_BASE): flags_n = curbyte;
                        (`TCP_WINDOW_SIZE_BASE + 0): window_size_n[15:8] = curbyte;
                        (`TCP_WINDOW_SIZE_BASE + 1): window_size_n[7:0]  = curbyte;
                        (`TCP_URGENT_PTR_BASE + 0): urgent_n[15:8] = curbyte;
                        (`TCP_URGENT_PTR_BASE + 1): urgent_n[7:0]  = curbyte;
                    endcase

                    // --- checksum ---
                    if (!odd_byte_valid_n) begin
                        odd_byte_n = curbyte;
                        odd_byte_valid_n = 1'b1;
                    end else begin
                        chksum_acc_n = chksum_acc_n + {odd_byte_n, curbyte};
                        chksum_acc_n = (chksum_acc_n & 16'hFFFF) + (chksum_acc_n >> 16);
                        odd_byte_valid_n = 0;
                    end

                    // Accumulate header bytes
                    header_bytes_accum_n = header_bytes_accum_n + 1;

                    valid_idx++; // only increment for valid bytes
                end
            end

            byte_offset_n = byte_offset_r + valid_idx;

            // State transitions
            case (state_r)
                S_HEADER: begin
                    if (header_bytes_accum_n >= header_bytes_needed_n && header_bytes_needed_n != 0) begin
                        // Compute leftover bytes from header accumulation
                        automatic int first_forward_bytes = header_bytes_accum_n - header_bytes_needed_n;
                        forwarded_bytes_n = forwarded_bytes_r + first_forward_bytes;

                        // Move to forward state
                        state_n = (s_axis.tlast) ? S_WAIT : S_FORWARD;

                        // Set tkeep for first beat
                        if (first_forward_bytes == 0)
                            m_axis_keep_n = '0; // upper N bits
                        else if (first_forward_bytes > 0) begin
                            //m_axis.tkeep = ({BYTES{1'b1}} << (BYTES - first_forward_bytes)); // upper N bits
                            m_axis_keep_n = ({BYTES{1'b1}} >> (BYTES - first_forward_bytes)); // upper N bits
                            m_axis_data_n = (m_axis_data_n >> ((BYTES - first_forward_bytes)*8)); // upper N bits
                            m_axis_valid_n = 1;
                        end else begin
                            m_axis_keep_n = {BYTES{1'b1}}; // full beat
                            m_axis_valid_n = 1;
                        end
                    end
                end

                S_FORWARD: begin
                    // Default tkeep = all bytes valid
                    forwarded_bytes_n = forwarded_bytes_n + valid_idx;

                    m_axis_valid_n         = 1;

                    if (s_axis.tlast && s_axis.tvalid) begin
                        state_n = S_WAIT;
                        m_axis_last_n = 1;
                    end
                    
                end
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
            chksum_acc_r <= 0;
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
            meta_checksum_valid <= 0;
            meta_checksum_ok <= 0;
        end else begin
            // Latch state
            state_r             <= state_n;
            byte_offset_r       <= byte_offset_n;
            dst_port_r           <= dst_port_n; src_port_r <= src_port_n;
            header_length_r <= header_length_n; urgent_r <= urgent_n;
            chksum_acc_r        <= chksum_acc_n; odd_byte_valid_r <= odd_byte_valid_n; odd_byte_r <= odd_byte_n;
            header_bytes_needed_r <= header_bytes_needed_n; header_bytes_accum_r <= header_bytes_accum_n;
            seq_num_r <= seq_num_n; ack_num_r <= ack_num_n; flags_r <= flags_n; window_size_r <= window_size_n;
            forwarded_bytes_r <= forwarded_bytes_n;

            m_axis.tdata <= m_axis_data_n;
            m_axis.tkeep <= m_axis_keep_n;
            m_axis.tvalid <= m_axis_valid_n;
            m_axis.tlast  <= m_axis_last_n;

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
            else if (s_axis.tlast && s_axis.tvalid) begin
                // checksum calculation
                logic [15:0] sum16;
                if (odd_byte_valid_n)
                begin
                    sum16 = chksum_acc_n + (odd_byte_n<<8);
                end
                else
                    sum16 = chksum_acc_n;
            
                sum16 = sum16[15:0] + (sum16 >> 16);
                sum16 = sum16[15:0] + (sum16 >> 16);
                meta_checksum_ok    <= (sum16 == 16'hFFFF);
                meta_checksum_valid <= 1;
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
