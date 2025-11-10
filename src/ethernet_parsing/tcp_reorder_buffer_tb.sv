`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"
`include "tcp_reorder_buffer.sv"

`define NUM_FRAMES 10
`define BUF_DEPTH  1024
`define MESSAGE_LEN 200  // total bytes in the message

module tcp_reorder_buffer_tb;

    parameter int DATA_WIDTH = `INPUTWIDTH;
    parameter int BYTES      = DATA_WIDTH/8;

    logic clk;
    logic rst_n;

    // AXI interfaces
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) s_axis_if();
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) m_axis_if();

    // DUT sequence interface
    logic [31:0] seq_start, seq_base;
    logic        base_valid;

    logic [31:0] window_size;

    // Instantiate DUT
    tcp_reorder_buffer #(
        .DATA_WIDTH(DATA_WIDTH),
        .DEPTH      (`BUF_DEPTH),
        .SEQ_BITS   (32)
    ) dut (
        .clk        (clk),
        .rst_n      (rst_n),
        .s_axis     (s_axis_if),
        .m_axis     (m_axis_if),
        .seq_base   (seq_base),
        .base_valid (base_valid),
        .seq_start  (seq_start),
        .window_size(window_size)
    );

    // Capture output bytes
    byte rx_buffer[$];

    // -----------------------------
    // Clock & reset
    initial clk = 0;
    always #5 clk = ~clk;

    // Capture m_axis output
    always_ff @(posedge clk) begin
        if (m_axis_if.tvalid && m_axis_if.tready) begin
            for (int i = 0; i < BYTES; i++) begin
                if (m_axis_if.tkeep[i])
                    rx_buffer.push_back(m_axis_if.tdata[8*(i) +: 8]);
            end
        end
    end

    // -----------------------------
    // Helper: send single AXI beat
    task automatic send_word(
        input logic [DATA_WIDTH-1:0] tdata,
        input logic [BYTES-1:0]      tkeep,
        input bit                    tlast
    );
        begin
            s_axis_if.tdata  = tdata;
            s_axis_if.tkeep  = tkeep;
            s_axis_if.tvalid = 1'b1;
            s_axis_if.tlast  = tlast;
            @(posedge clk);
            while (!s_axis_if.tready) @(posedge clk);
            s_axis_if.tvalid = 0;
            s_axis_if.tlast  = 0;
            s_axis_if.tdata  = '0;
            s_axis_if.tkeep  = '0;
        end
    endtask

    // -----------------------------
    // Send full frame with seq_start
    task automatic send_frame(byte payload[], int len, logic [31:0] frame_seq);
        logic [DATA_WIDTH-1:0] tdata;
        logic [BYTES-1:0] tkeep;
        int i, b;

        seq_start   = frame_seq;
        @(posedge clk);

        for (i = 0; i < len; i += BYTES) begin
            int bytes_in_beat = (i+BYTES <= len) ? BYTES : (len-i);
            tdata = '0;
            tkeep = '0;
            for (b = 0; b < bytes_in_beat; b++) begin
                tdata = tdata | (payload[i+b] << ((b)*8));
                tkeep[b] = 1'b1;
            end
            send_word(tdata, tkeep, (i+BYTES >= len));
        end
    endtask

    // -----------------------------
    // Test driver
    initial begin
        byte message[$];
        // Slice message into frames
        typedef struct {
            byte payload[$];
            int  len;
            logic [31:0] seq_start;
        } frame_t;

        automatic frame_t frames[$];

        automatic int pos = 0;
        automatic int base_seq = 32'h1000;
        automatic int waited = 0;
        automatic int timeout = 64'd200000000000;
        automatic int message_len = 200; // example length

        // Fill message with random bytes
        for (int i = 0; i < message_len; i++)
            message.push_back($urandom_range(0,255));

        while (pos < message_len) begin
            automatic frame_t f;
            f.len = $urandom_range(8, 32);                  // random frame length
            if (pos + f.len > message_len) f.len = message_len - pos;
            f.payload = {};
            for (int k=0; k<f.len; k++)
                f.payload.push_back(message[pos + k]);
            f.seq_start = base_seq + pos;                   // absolute byte seq
            frames.push_back(f);
            pos += f.len;
        end

        // -----------------------------
        // Shuffle frames for out-of-order delivery
        // -----------------------------
        for (int i = 0; i < frames.size(); i++) begin
            automatic int j = $urandom_range(0, frames.size()-1);
            automatic frame_t tmp = frames[i];
            frames[i] = frames[j];
            frames[j] = tmp;
        end

        // -----------------------------
        // Send frames
        // -----------------------------
        // Send frames
        rx_buffer = {};
        m_axis_if.tready = 1;

        s_axis_if.tdata  = '0;
        s_axis_if.tkeep  = '0;
        s_axis_if.tvalid = 0;
        s_axis_if.tlast  = 0;
        s_axis_if.tuser  = '0;

        seq_start   = 0;
        base_valid = 0;

        rst_n = 0;
        repeat(5) @(posedge clk);
        rst_n = 1;
        repeat(5) @(posedge clk);


        seq_base = base_seq;
        base_valid = 1;
        @(posedge clk);
        base_valid = 0;

        for (int i = 0; i < frames.size(); i++)
        begin
            send_frame(frames[i].payload, frames[i].len, frames[i].seq_start);
        end


        repeat(600) @(posedge clk); // wait for processing

        // Check result
        if (rx_buffer.size() != message.size())
            $display("TOTAL SIZE MISMATCH: expected %0d, got %0d", message.size(), rx_buffer.size());
        else begin
            automatic bit match = 1;
            for (int i=0; i<message.size(); i++) begin
                if (rx_buffer[i] !== message[i]) begin
                    $display("BYTE MISMATCH at %0d: expected %02x got %02x", i, message[i], rx_buffer[i]);
                    match = 0;
                end
            end
            if (match) $display("PASS: all bytes match reordered output!");
        end

        $display("TEST COMPLETE");
        $stop(0);
    end

endmodule
