`timescale 1ns/1ps
`include "ethernet_info.svh"

module tcp_brain #(
    parameter int DATA_WIDTH        = `INPUTWIDTH,
    parameter int INSTRUCTION_WIDTH = 8, // Typo fixed: INSTURCTION_WIDTH
    parameter int SEQ_BITS   = 32
)(
    input  logic clk,
    input  logic rst_n,

    // AXI4-Stream slave (commands from App)
    input  logic [DATA_WIDTH-1:0] instruction_axis_tdata,
    input  logic                  instruction_axis_tvalid,
    output logic                  instruction_axis_tready,
    input  logic                  instruction_axis_tlast,

    // AXI4-Stream master (to App - data RECEIVED)
    output logic [DATA_WIDTH-1:0] response_axis_tdata,
    output logic                  response_axis_tvalid,
    input  logic                  response_axis_tready,
    output logic                  response_axis_tlast,

    // TCP sender interface
    output logic               sender_start,
    output tcp_packet_info_s   sender_info,
    input  logic               sender_busy,

    // Connection info (latched on instruction)
    input  tcp_command_info     in_info,

    input  logic [31:0]         window_size,  // remaining byte space
    input  logic [31:0]         expected_ack,
    input  logic                ack_done,
    output logic [SEQ_BITS-1:0] seq_base,   // starting seq# of the base (anchor)
    output logic                base_valid, // pulse when seq_base is valid

    // Metadata inputs (from tcp_parser)
    input  logic                meta_valid,
    output logic                meta_ready,
    input  logic [31:0]         meta_seq_num,
    input  logic [31:0]         meta_ack_num,
    input  logic [7:0]          meta_flags,
    input  logic [15:0]         meta_window_size,
    input  logic [15:0]         meta_payload_len
);

    localparam int BYTES              = DATA_WIDTH/8;
    localparam int TIMEOUT            = 1000000000; // 1 second at 1GHz
    localparam int TIME_WAIT_TIMEOUT  = 2 * TIMEOUT;  // 2*MSL placeholder
    localparam MAX_FAILED_ATTEMPS = 3;

    // --- Application Command Opcodes ---
    localparam CMD_CONNECT = 8'h01;
    localparam CMD_CLOSE   = 8'h02;
    localparam CMD_SEND    = 8'h03;

    logic [3:0] state_r, state_n;

    // --- TCP State Variables ---
    logic [31:0] client_seq_num;    // Our *next* sequence number to send
    logic [31:0] server_seq_num;    // The *next* sequence number we *expect* from server
    logic [31:0] last_ack_received; // Last ACK number we got from them
    logic [15:0] server_window;     // Their last advertised window
    logic [31:0] client_isn;        // Our initial sequence number

    // --- Helpers ---
    logic [31:0] timer;
    logic [3:0]  num_attempts;
    logic        send_dup_ack;


    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_r           <= S_CLOSED;
            client_isn        <= 32'h12345678; // Example ISN
            client_seq_num    <= 0;
            server_seq_num    <= 0;
            last_ack_received <= 0;
            server_window     <= 0;
            sender_start      <= 0;
            timer             <= 0;
            num_attempts      <= 0;
            send_dup_ack      <= 0;
            instruction_axis_tready <= 0;
        end else begin

            // --- Default Assignments (prevent latches/multi-drivers) ---
            state_r                 <= state_r;
            sender_start            <= 0;
            instruction_axis_tready <= 0;
            send_dup_ack            <= 0;
            meta_ready              <= 0;

            // This is the packet info we will send *if* sender_start is high
            // It latches the previous value by default.
            sender_info             <= sender_info;
            case(state_r)
                //-----------------------------------------
                S_CLOSED: begin
                    // Ready to accept a "connect" command
                    instruction_axis_tready <= 1;

                    if (instruction_axis_tvalid && instruction_axis_tdata == CMD_CONNECT) begin
                        // Latch connection info and ISN
                        sender_info.src_mac <= in_info.src_mac;
                        sender_info.dst_mac <= in_info.dst_mac;
                        sender_info.src_port <= in_info.src_port;
                        sender_info.dst_port <= in_info.dst_port;
                        sender_info.src_ip   <= in_info.src_ip;
                        sender_info.dst_ip   <= in_info.dst_ip;
                        sender_info.window   <= window_size[15:0]; // Our receive window

                        // Prepare SYN packet fields and schedule a one-cycle prepare
                        client_seq_num <= client_isn + 1; // Set our starting sequence number (SYN consumes one seq)
                        sender_info.seq_num    <= client_isn;
                        sender_info.ack_num    <= 0;
                        sender_info.tcp_flags  <= (1<<`TCP_FLAG_SYN);
                        sender_info.payload_len <= 0;

                        state_n   <= S_SYN_SENT;
                        state_r         <= S_PREPARE_SEND;
                        timer           <= TIMEOUT;
                        num_attempts    <= 0;
                    end
                end

                //-----------------------------------------
                S_PREPARE_SEND: begin
                    // Pulse sender_start for one cycle, then go wait-for-sender
                    sender_start <= 1;
                    sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed

                    // don't accept metadata while initiating send
                    base_valid <= 0;
                    // move into waiting state while preserving the pending logical next state
                    state_r <= S_WAITING_TO_SEND;
                end

                //-----------------------------------------
                S_WAITING_TO_SEND: begin
                    // Wait for the tcp_sender module to finish sending the packet
                    if (!sender_busy) begin
                        state_r <= S_NOTIFY_FPGA; // Go to the state we saved
                        response_axis_tvalid <= 1;
                        response_axis_tdata  <= {4'b0, state_n}; // Indicate packet sent
                        response_axis_tlast  <= 1;
                        sender_start         <= 0;
                    end
                    base_valid <= 0;
                end

                S_NOTIFY_FPGA: begin
                    if (response_axis_tready) begin
                        response_axis_tvalid <= 0;
                        state_r <= state_n;
                    end
                end

                //-----------------------------------------
                S_SYN_SENT: begin
                    // Ready to process the parser's response
                    if (meta_valid) begin
                        meta_ready <= 1;
                        if (meta_flags[`TCP_FLAG_RST]) begin
                            // Connection refused
                            state_r <= S_CLOSED;
                        end
                        // Check for SYN-ACK and correct ACK number
                        else if (meta_flags[`TCP_FLAG_SYN] && meta_flags[`TCP_FLAG_ACK] && meta_ack_num == (client_isn + 1)) begin
                            // --- Connection Established! ---
                            server_seq_num    <= meta_seq_num + 1;
                            seq_base         <= meta_seq_num + 1;
                            base_valid        <= 1;

                            last_ack_received <= meta_ack_num;
                            // Our SYN is now ACKed; set our next sequence base
                            client_seq_num    <= meta_ack_num;
                            server_window     <= meta_window_size;

                            // Send final ACK of 3-way handshake. Use the
                            // meta values directly here because client_seq_num
                            // and server_seq_num are updated in this same
                            // sequential block (non-blocking), so reading the
                            // registers would return old values in this cycle.
                            sender_info.seq_num    <= meta_ack_num;            // our updated next seq
                            sender_info.ack_num    <= (meta_seq_num + 1);     // acknowledge their SYN
                            sender_info.tcp_flags  <= 1<<`TCP_FLAG_ACK;
                            sender_info.payload_len <= 0;

                            // move to prepare-send so sender_info is stable when pulsed
                            state_n <= S_ESTABLISHED;
                            sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                            state_r      <= S_PREPARE_SEND;
                        end
                    end
                    else if (timer > 0) begin
                        timer <= timer - 1;
                    end
                    else if (num_attempts < MAX_FAILED_ATTEMPS) begin
                        // --- Timeout: Resend SYN ---
                        num_attempts   <= num_attempts + 1;
                        // resend: ensure sender_info is stable before pulsing
                        state_n   <= S_SYN_SENT;
                        timer           <= TIMEOUT;
                        state_r         <= S_PREPARE_SEND;
                    end
                    else begin
                        // Max attempts failed
                        state_r <= S_CLOSED;
                    end
                end
                //-----------------------------------------
                S_ESTABLISHED: begin
                    // --- We are connected and can send/receive data ---
                    // Ready for data from App *if* sender is free

                    // Ready for "close" command
                    instruction_axis_tready <= 1;
                    meta_ready<= 0;

                    if (meta_valid&~meta_ready) begin
                        meta_ready <= 1;
                        // --- Priority 1: Handle Incoming Packets ---
                        if (meta_flags[`TCP_FLAG_RST]) begin
                            state_r <= S_CLOSED;
                        end
                        else if (meta_flags[`TCP_FLAG_FIN]) begin
                            // --- Passive Close: Server wants to close ---
                            server_seq_num <= meta_seq_num + 1; // FIN counts as 1 byte

                            // Send ACK for their FIN
                            sender_info.seq_num    <= client_seq_num;
                            sender_info.ack_num    <= server_seq_num;
                            sender_info.tcp_flags  <= 1<<`TCP_FLAG_ACK;
                            sender_info.payload_len <= 0;

                            state_n <= S_CLOSE_WAIT;
                            sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                            state_r      <= S_PREPARE_SEND;
                        end
                        else begin
                            // --- Data or ACK Packet ---
                            // 1. Process their ACK field
                            if (meta_ack_num > last_ack_received) begin
                                last_ack_received <= meta_ack_num;
                                server_window     <= meta_window_size;
                            end

                            // 2. Process their Data field
                            if (meta_payload_len > 0) begin
                                if (meta_seq_num == server_seq_num) begin
                                    // --- Good, in-order data ---
                                    // The data path is combinational (s_axis_rx -> response_axis)
                                    // We just need to update our expected sequence number
                                    state_r <= S_WAIT_FOR_ACK;
                                end
                                else begin
                                    // --- Out-of-order or retransmitted data ---
                                    // We are not ready for this. Send a duplicate ACK
                                    // to tell the server what we *are* waiting for.
                                    send_dup_ack <= 1;
                                end
                            end
                        end // end else (data/ack)
                    end // end if(meta_valid)
                    else if (instruction_axis_tvalid && instruction_axis_tdata == CMD_SEND) begin
                        // --- Priority 2: Handle Outgoing Data from App ---
                        // (Assuming sender module will read from s_axis based on payload_len)
                        // (This assumes we know the length *before* sending)
                        // (This logic assumes `in_info.payload_len` is updated by the app)

                        sender_info.seq_num    <= client_seq_num;
                        sender_info.ack_num    <= server_seq_num; // Piggyback ACK
                        sender_info.tcp_flags  <= (1<<`TCP_FLAG_ACK) | (1<<`TCP_FLAG_PSH);
                        sender_info.payload_len <= in_info.payload_len;

                        client_seq_num <= client_seq_num + {16'b0, in_info.payload_len};

                        // prepare send so sender_info is stable for one cycle
                        state_n <= S_ESTABLISHED;
                        sender_info.tcp_checksum <= in_info.tcp_checksum; // No payload, checksum not needed
                        state_r <= S_PREPARE_SEND;
                    end
                    else if (instruction_axis_tvalid && instruction_axis_tdata == CMD_CLOSE) begin
                        // --- Priority 3: Handle Active Close (App wants to close) ---
                        sender_info.seq_num    <= client_seq_num;
                        sender_info.ack_num    <= server_seq_num;
                        sender_info.tcp_flags  <= (1<<`TCP_FLAG_FIN) | (1<<`TCP_FLAG_ACK);
                        sender_info.payload_len <= 0;

                        client_seq_num <= client_seq_num + 1; // FIN counts as 1 byte

                        state_n <= S_FIN_WAIT_1;
                        sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                        state_r      <= S_PREPARE_SEND;
                        timer        <= TIMEOUT;
                    end

                    else if (send_dup_ack) begin
                        // --- Priority 4: Send Duplicate ACK ---
                        sender_info.seq_num    <= client_seq_num;
                        sender_info.ack_num    <= server_seq_num; // Send *expected* number cfb45248
                        sender_info.tcp_flags  <= 1<<`TCP_FLAG_ACK;
                        sender_info.payload_len <= 0;

                        state_n <= S_ESTABLISHED;
                        sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                        state_r      <= S_PREPARE_SEND;
                    end
                end // end S_ESTABLISHED

                S_WAIT_FOR_ACK: begin
                    if (ack_done) begin
                        server_seq_num <= expected_ack;

                        // Send ACK (or piggyback on next data packet)
                        // For simplicity, we send an ACK immediately.
                        sender_info.seq_num    <= client_seq_num;
                        sender_info.ack_num    <= expected_ack;
                        sender_info.tcp_flags  <= 1<<`TCP_FLAG_ACK;
                        sender_info.payload_len <= 0;

                        state_n <= S_ESTABLISHED;
                        sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                        state_r  <= S_PREPARE_SEND;
                    end
                end

                // --- PASSIVE CLOSE STATES ---
                //-----------------------------------------
                S_CLOSE_WAIT: begin
                    // Server sent FIN, we ACKed.
                    // We now wait for our *own* application to be ready to close.
                    instruction_axis_tready <= 1;

                    if (instruction_axis_tvalid && instruction_axis_tdata == CMD_CLOSE) begin
                        // App is done. Send our FIN.
                        sender_info.seq_num    <= client_seq_num;
                        sender_info.ack_num    <= server_seq_num;
                        sender_info.tcp_flags  <= (1<<`TCP_FLAG_FIN )|( 1<<`TCP_FLAG_ACK);
                        sender_info.payload_len <= 0;

                        client_seq_num <= client_seq_num + 1; // FIN counts as 1 byte

                        state_n <= S_LAST_ACK;
                        sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                        state_r      <= S_PREPARE_SEND;
                        timer        <= TIMEOUT;
                        num_attempts <= 0;
                    end
                end

                //-----------------------------------------
                S_LAST_ACK: begin
                    // We sent our FIN, waiting for the final ACK.
                    meta_ready <= 1;

                    if (meta_valid && meta_flags[`TCP_FLAG_ACK] && meta_ack_num == client_seq_num) begin
                        // All done.
                        state_r <= S_CLOSED;
                    end
                    else if (timer > 0) begin
                        timer <= timer - 1;
                    end
                    else if (num_attempts < MAX_FAILED_ATTEMPS) begin
                         // --- Timeout: Resend FIN ---
                        num_attempts <= num_attempts + 1;
                        // resend FIN: ensure sender_info is stable before pulsing
                        state_n <= S_LAST_ACK;
                        sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                        timer        <= TIMEOUT;
                        state_r      <= S_PREPARE_SEND;
                    end
                    else begin
                        state_r <= S_CLOSED; // Give up
                    end
                end

                // --- ACTIVE CLOSE STATES ---
                //-----------------------------------------
                S_FIN_WAIT_1: begin
                    // We sent a FIN, waiting for ACK or FIN+ACK.
                    meta_ready <= 1;

                    if (meta_valid) begin
                        if (meta_flags[`TCP_FLAG_ACK] && meta_ack_num == client_seq_num) begin
                            last_ack_received <= meta_ack_num;

                            if (meta_flags[`TCP_FLAG_FIN]) begin
                                // --- Simultaneous Close ---
                                server_seq_num <= meta_seq_num + 1;
                                // Send ACK for their FIN
                                sender_info.seq_num    <= client_seq_num;
                                sender_info.ack_num    <= server_seq_num;
                                sender_info.tcp_flags  <= `TCP_FLAG_ACK;
                                sender_info.payload_len <= 0;

                                sender_start <= 1;
                                sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                                state_r      <= S_WAITING_TO_SEND;
                                state_n      <= S_TIME_WAIT;
                                timer        <= TIME_WAIT_TIMEOUT;
                            end
                            else begin
                                // --- Got ACK, wait for FIN ---
                                state_r <= S_FIN_WAIT_2;
                            end
                        end
                        // (Could also get FIN w/o ACK... simplified for now)
                    end
                    else if (timer > 0) begin
                        timer <= timer - 1;
                    end
                    else begin
                        // --- Timeout: Resend FIN ---
                        // (Assuming num_attempts logic, omitted for brevity)
                        // resend FIN: ensure sender_info is stable before pulsing
                        state_n <= S_FIN_WAIT_1;
                        sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                        timer        <= TIMEOUT;
                        state_r      <= S_PREPARE_SEND;
                    end
                end

                //-----------------------------------------
                S_FIN_WAIT_2: begin
                    // We sent FIN, got ACK. Now waiting for *their* FIN.
                    meta_ready <= 1;

                    if (meta_valid && meta_flags[`TCP_FLAG_FIN]) begin
                        server_seq_num <= meta_seq_num + 1;

                        // Send ACK for their FIN
                        sender_info.seq_num    <= client_seq_num;
                        sender_info.ack_num    <= server_seq_num;
                        sender_info.tcp_flags  <= `TCP_FLAG_ACK;
                        sender_info.payload_len <= 0;

                        state_n <= S_TIME_WAIT;
                        sender_info.tcp_checksum <= 16'h0000; // No payload, checksum not needed
                        state_r      <= S_PREPARE_SEND;
                        timer        <= TIME_WAIT_TIMEOUT; // Start 2*MSL timer
                    end
                end

                //-----------------------------------------
                S_TIME_WAIT: begin
                    // We sent final ACK, just waiting 2*MSL to catch stragglers.
                    // No new connections can be formed on this (src_ip, src_port, dst_ip, dst_port) tuple.
                    if (timer > 0) begin
                        timer <= timer - 1;
                    end
                    else begin
                        state_r <= S_CLOSED;
                    end
                end

                // Handle undefined states
                default: begin
                    state_r <= S_CLOSED;
                end

            endcase
        end
    end

endmodule
