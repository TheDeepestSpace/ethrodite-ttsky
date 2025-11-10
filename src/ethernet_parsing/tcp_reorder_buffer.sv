`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"

module tcp_reorder_buffer #(
    parameter int DATA_WIDTH = `INPUTWIDTH, // expect 64
    parameter int DEPTH      = 4096,        // power-of-two number of words
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

    output logic [31:0]         window_size,  // remaining byte space
    output logic [31:0]         ack_out,
    output logic                ack_done
);

    // ---------- parameters /locals ----------
    localparam int BYTES     = DATA_WIDTH/8;           // 8 for 64-bit
    localparam int PACKET_DEPTH = (DEPTH*8 + DATA_WIDTH - 1) / DATA_WIDTH;
    localparam int ADDR_BITS = $clog2(PACKET_DEPTH);
    localparam int OFFSET_BITS = $clog2(BYTES);        // 3 for 8

    // ---------- memories (BRAM-friendly) ----------
    // Data and keep memories: prefer block RAMs (M9K)
    (* ramstyle = "M9K" *) logic [DATA_WIDTH-1:0] data_mem [0:PACKET_DEPTH-1];
    (* ramstyle = "M9K" *) logic [BYTES-1:0]      keep_mem [0:PACKET_DEPTH-1];

    // ---------- control regs ----------
    logic [SEQ_BITS-1:0] base_seq_reg;
    logic                base_defined;

    logic [31:0] used_bytes;

    // --- staging for incoming beat (one cycle capture) ---
    logic [SEQ_BITS-1:0]  prev_seq;   // byte-address of first byte in staged beat

    logic [SEQ_BITS-1:0] expected_seq_reg;

    // RMW addresses and offsets
    logic [OFFSET_BITS-1:0] first_offset;

    // temporary merged values
    logic [DATA_WIDTH-1:0] prev_data, curr_data;
    logic [BYTES-1:0]      prev_keep, curr_keep;

    logic [ADDR_BITS-1:0] read_raddr, write_addr, reset_index;
    logic reset_done;
    logic [SEQ_BITS-1:0] offset_bytes;
    
    assign offset_bytes = seq_start - base_seq_reg;

    assign ack_out = expected_seq_reg + base_seq_reg;

    // helper function: popcount of keep mask
    function automatic int popcount_bytes(input logic [BYTES-1:0] k);
        int cnt; cnt=0;
        for (int i=0;i<BYTES;i++) if (k[i]) cnt++;
        return cnt;
    endfunction

    assign window_size  = DEPTH - used_bytes;

    // ---------- upstream ready logic ----------
    // Accept when base set, not staging, and enough free bytes exist for incoming beat.
    wire [31:0] free_bytes = (DEPTH) - used_bytes;
    assign s_axis.tready = base_defined && (prev_seq == seq_start);

    always_ff @(posedge clk) begin
        if (!rst_n) begin
            write_addr <= 0;
            prev_seq   <= 0;
            prev_data  <= '0;
            prev_keep  <= '0;
            curr_data  <= '0;
            curr_keep  <= '0;
            base_defined <= 0;
            reset_index <= '0;
            reset_done <= 0;
        end else if (!reset_done) begin
            keep_mem[reset_index] <= '0;
            data_mem[reset_index] <= '0;
            reset_index <= reset_index + 1;
            if (reset_index == PACKET_DEPTH-1)
                reset_done <= 1;
        end else if (base_valid) begin
            base_seq_reg <= seq_base;
            base_defined <= 1;
            expected_seq_reg <= '0;
            m_axis.tvalid <= 0;
            read_raddr <= '0;
            ack_done <= 0;
        end if (base_defined) begin
            if (seq_start != prev_seq) begin
                // New segment: reset write pointer and offsets
                prev_seq     <= seq_start;
                write_addr   <= (offset_bytes) >> OFFSET_BITS;

                ack_done     <= 0;

                first_offset <= offset_bytes[OFFSET_BITS-1:0];     // byte index inside word

                // flushing our buffer and clearing it for the new sequence number
                data_mem[write_addr] <= (curr_data | prev_data);
                keep_mem[write_addr] <= (curr_keep | prev_keep);
                curr_data    <= data_mem[(offset_bytes) >> OFFSET_BITS];
                curr_keep    <= keep_mem[(offset_bytes) >> OFFSET_BITS];
                prev_data    <= '0;
                prev_keep    <= '0;
            end else if ((s_axis.tvalid && s_axis.tkeep != '0) || (prev_keep != '0)) begin
                // Locals
                logic [DATA_WIDTH-1:0] merged_data;
                logic [BYTES-1:0]      merged_keep;
                logic [DATA_WIDTH-1:0] prev_data_next;
                logic [BYTES-1:0]      prev_keep_next;
                logic [DATA_WIDTH-1:0] keep_mask;
                logic [DATA_WIDTH-1:0] shifted_data;
                logic [DATA_WIDTH-1:0] shifted_mask;
                automatic int total_bytes, valid_bytes, leftover_bytes;

                // Debug
                // ------------------------------------------------------------------
                // 1. Build keep mask (8 bits per valid byte)
                // ------------------------------------------------------------------
                for (int i = 0; i < BYTES; i++) begin
                    keep_mask[i*8 +: 8] = {8{s_axis.tkeep[i]}};
                end

                // ------------------------------------------------------------------
                // 2. Shift and mask incoming data to zero invalid bits
                // ------------------------------------------------------------------
                shifted_data = ((s_axis.tdata & keep_mask) << (first_offset * 8));
                shifted_mask = (keep_mask << (first_offset * 8));

                // ------------------------------------------------------------------
                // 3. Merge with current and previous data safely
                //    - Clear overlapping byte lanes in curr_data before OR
                // ------------------------------------------------------------------
                merged_data = ((curr_data & ~shifted_mask) | shifted_data | prev_data);
                merged_keep = (curr_keep | prev_keep) | (s_axis.tkeep << first_offset);

                // ------------------------------------------------------------------
                // 4. Compute leftover bytes for next beat
                // ------------------------------------------------------------------
                valid_bytes = popcount_bytes(s_axis.tkeep);
                leftover_bytes = (first_offset + valid_bytes > BYTES)
                                ? (first_offset + valid_bytes - BYTES)
                                : 0;

                // ------------------------------------------------------------------
                // 5. Prepare data for next beat (carry-over)
                // ------------------------------------------------------------------
                if (leftover_bytes == 0) begin
                    prev_data_next = '0;
                    prev_keep_next = '0;
                end else begin
                    // Mask invalid bytes in shifted-down region too
                    logic [DATA_WIDTH-1:0] next_keep_mask;
                    for (int i = 0; i < BYTES; i++)
                        next_keep_mask[i*8 +: 8] = {8{s_axis.tkeep[i]}};

                    prev_data_next = ((s_axis.tdata & next_keep_mask)
                                    >> ((valid_bytes - leftover_bytes) * 8));
                    prev_keep_next = (s_axis.tkeep >> (valid_bytes - leftover_bytes));
                end

                // ------------------------------------------------------------------
                // 6. Update prev_* and write current word
                // ------------------------------------------------------------------
                prev_data <= prev_data_next;
                prev_keep <= prev_keep_next;

                total_bytes = first_offset + valid_bytes;

                data_mem[write_addr] <= merged_data;
                keep_mem[write_addr] <= merged_keep;

                // ------------------------------------------------------------------
                // 7. Advance pointer or update curr_data inline
                // ------------------------------------------------------------------
                if (total_bytes >= BYTES) begin
                    write_addr <= (write_addr + 1) % PACKET_DEPTH;
                    curr_data  <= data_mem[(write_addr + 1) % PACKET_DEPTH];
                    curr_keep  <= (((write_addr + 1) % PACKET_DEPTH == read_raddr) && m_axis.tready)
                                ? '0
                                : keep_mem[(write_addr + 1) % PACKET_DEPTH];
                    first_offset <= total_bytes - BYTES;
                end else begin
                    curr_data  <= merged_data;
                    curr_keep  <= merged_keep;
                    first_offset <= total_bytes;
                end
            end

        end
    end

    // ---------- Egress / readout path ----------
    // read_raddr is word index for next output
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            read_raddr <= '0;
            m_axis.tvalid <= 1'b0;
            m_axis.tdata <= '0;
            m_axis.tkeep <= '0;
            expected_seq_reg <= '0;
            ack_done <= 0;
        end else if (!base_valid) begin
            // default
            m_axis.tvalid <= 1'b0;
            m_axis.tdata  <= '0;
            m_axis.tkeep  <= '0;

            // if current slot has any valid bytes, we can present it
            if (~(read_raddr == write_addr && s_axis.tvalid) && base_defined && seq_start == prev_seq) begin
                if (m_axis.tready) begin
                    // consume
                    automatic int bytes_out = popcount_bytes(keep_mem[read_raddr]);
                    m_axis.tdata  <= data_mem[read_raddr];//(data_mem[read_raddr])>>((expected_seq_reg % BYTES)*8);
                    m_axis.tkeep  <= keep_mem[read_raddr];//(keep_mem[read_raddr])>>((expected_seq_reg % BYTES));
                    m_axis.tvalid <= keep_mem[read_raddr] != 0;
                    ack_done <= (keep_mem[read_raddr] == 0);
                    
                    // increment read_raddr only if we have consumed all bytes in the current word
                    if ((expected_seq_reg + bytes_out)% DEPTH >= (read_raddr * BYTES + BYTES)% DEPTH) begin
                        read_raddr <= (read_raddr + 1) % PACKET_DEPTH;
                    end

                    expected_seq_reg <= (expected_seq_reg + bytes_out);

                    // clear slot
                    keep_mem[read_raddr] <= '0;
                end
            end
        end
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            used_bytes <='0;
        end else begin
            // update used_bytes based on incoming and outgoing data
            automatic int in_bytes, out_bytes;
            in_bytes = 0;
            out_bytes = 0;

            if (s_axis.tvalid && s_axis.tready) begin
                in_bytes = popcount_bytes(s_axis.tkeep);
            end

            if (m_axis.tvalid && m_axis.tready) begin
                out_bytes = popcount_bytes(m_axis.tkeep);
            end

            used_bytes <= used_bytes + in_bytes - out_bytes;
        end
    end
endmodule
