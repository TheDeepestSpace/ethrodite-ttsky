`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"
`include "uart_core.sv"
`include "uart_tcp_mux.sv"
`include "tcp_top.sv"

module uart_top_tb;

    parameter int DATA_WIDTH = 64;
    parameter int BYTES = DATA_WIDTH / 8;
    parameter int BAUD_RATE = 115200;
    parameter int CLK_FREQ = 50000000;
    parameter int BAUD_PERIOD = CLK_FREQ / BAUD_RATE; // Clock cycles per UART bit

    // Clock & reset
    logic clk;
    logic rst_n;

    // UART physical interface
    logic uart_rx, uart_tx;
    logic [7:0] debug_status;
    logic connection_active;

    // DUT - Top-level UART + TCP wrapper
    uart_top #(
        .DATA_WIDTH(DATA_WIDTH),
        .BAUD_RATE(BAUD_RATE),
        .CLK_FREQ(CLK_FREQ)
    ) dut (
        .clk(clk),
        .rst_n(rst_n),
        .uart_rx(uart_rx),
        .uart_tx(uart_tx),
        .debug_status(debug_status),
        .connection_active(connection_active)
    );

    // Test data structures
    typedef struct {
        logic [7:0] pkt_type;
        byte data[];
        int data_len;
    } uart_packet_t;

    // Buffers for RX/TX data
    byte rx_frame_buffer[$];
    byte tx_frame_buffer[$];
    uart_packet_t received_packets[$];

    // Activity tracking
    logic [63:0] tick_count = 0;
    logic [63:0] last_activity = 0;
    logic update_activity = 0; // Signal to update activity from other processes
    logic tx_activity_pulse = 0; // Signal from TX monitor
    localparam int WATCHDOG_CYCLES = 200000;

    // Clock generation
    initial clk = 0;
    always #10 clk = ~clk; // 50MHz

    // Global tick counter and watchdog
    always_ff @(posedge clk) begin
        tick_count <= tick_count + 1;

        // Update last activity when signaled or TX activity detected
        if (update_activity || tx_activity_pulse) begin
            last_activity <= tick_count;
        end

        // Heartbeat every 50k cycles
        if ((tick_count % 50000) == 0) begin
            $display("[TB] %0t HEARTBEAT: tick=%0d uart_tx=%0b rx_buf=%0d tx_buf=%0d packets=%0d",
                $time, tick_count, uart_tx, rx_frame_buffer.size(), tx_frame_buffer.size(), received_packets.size());
        end

        // Watchdog timeout
        if (tick_count > 0 && (tick_count - last_activity) > WATCHDOG_CYCLES) begin
            $display("[TB][WATCHDOG] No activity for %0d cycles at time %0t", tick_count - last_activity, $time);
            last_activity <= tick_count;
        end
    end

    // Reset sequence
    initial begin
        rst_n = 0;
        uart_rx = 1; // UART idle high
        rx_frame_buffer = {};
        tx_frame_buffer = {};
        received_packets = {};
        update_activity = 0;

        repeat(10) @(posedge clk);
        rst_n = 1;
        repeat(10) @(posedge clk);

        $display("[TB] Starting UART TCP testbench");
        update_activity = 1;
        @(posedge clk);
        update_activity = 0;
    end

    // Task to send UART byte (9600 baud timing)
    task send_uart_byte(input logic [7:0] data);
        integer i;
        $display("[TB] Sending UART byte: 0x%02h", data);
        update_activity = 1;
        @(posedge clk);
        update_activity = 0;

        // Start bit
        uart_rx = 0;
        repeat(BAUD_PERIOD) @(posedge clk);

        // Data bits (LSB first)
        for (i = 0; i < 8; i++) begin
            uart_rx = data[i];
            repeat(BAUD_PERIOD) @(posedge clk);
        end

        // Stop bit
        uart_rx = 1;
        repeat(BAUD_PERIOD) @(posedge clk);
    endtask

    // Task to send complete UART packet
    task send_uart_packet(
        input logic [7:0] pkt_type,
        input byte data[],
        input int data_len
    );
        automatic logic [15:0] crc = 16'h0000; // Placeholder CRC
        integer i;

        $display("[TB] Sending UART packet: type=0x%02h len=%0d", pkt_type, data_len);

        // Start byte
        send_uart_byte(8'h5A);

        // Packet type
        send_uart_byte(pkt_type);

        // Length (big-endian)
        send_uart_byte(data_len[15:8]);
        send_uart_byte(data_len[7:0]);

        // Data payload
        for (i = 0; i < data_len; i++) begin
            send_uart_byte(data[i]);
        end

        // CRC (2 bytes)
        send_uart_byte(crc[15:8]);
        send_uart_byte(crc[7:0]);

        // Give some settling time
        repeat(BAUD_PERIOD * 2) @(posedge clk);
    endtask

    // Task to build complete Ethernet frame with TCP segment
    task build_ethernet_frame(
        input byte tcp_payload[],
        input int payload_len,
        input logic [47:0] src_mac,
        input logic [47:0] dst_mac,
        input logic [31:0] src_ip,
        input logic [31:0] dst_ip,
        input logic [15:0] src_port,
        input logic [15:0] dst_port,
        input logic [31:0] seq_num,
        input logic [31:0] ack_num,
        input logic [7:0] tcp_flags,
        output byte frame_bytes[]
    );
        automatic byte tmp[$];
        automatic int i, ip_len, tcp_len;
        automatic logic [15:0] ip_checksum, tcp_checksum;
        automatic logic [31:0] crc32;

        tmp = {};

        // Ethernet header (14 bytes)
        for (i = 5; i >= 0; i--) tmp.push_back(dst_mac[i*8 +: 8]);  // Dst MAC
        for (i = 5; i >= 0; i--) tmp.push_back(src_mac[i*8 +: 8]);  // Src MAC
        tmp.push_back(8'h08); tmp.push_back(8'h00);                 // EtherType (IPv4)

        // IPv4 header (20 bytes minimum)
        ip_len = 20 + 20 + payload_len; // IP header + TCP header + payload
        tmp.push_back(8'h45);           // Version + IHL
        tmp.push_back(8'h00);           // DSCP + ECN
        tmp.push_back(ip_len[15:8]);    // Total length
        tmp.push_back(ip_len[7:0]);
        tmp.push_back(8'h12); tmp.push_back(8'h34); // Identification
        tmp.push_back(8'h00); tmp.push_back(8'h00); // Flags + Fragment offset
        tmp.push_back(8'h40);           // TTL
        tmp.push_back(8'h06);           // Protocol (TCP)
        tmp.push_back(8'h00); tmp.push_back(8'h00); // Checksum (placeholder)
        for (i = 3; i >= 0; i--) tmp.push_back(src_ip[i*8 +: 8]);  // Src IP
        for (i = 3; i >= 0; i--) tmp.push_back(dst_ip[i*8 +: 8]);  // Dst IP

        // TCP header (20 bytes minimum)
        tmp.push_back(src_port[15:8]); tmp.push_back(src_port[7:0]); // Src port
        tmp.push_back(dst_port[15:8]); tmp.push_back(dst_port[7:0]); // Dst port
        for (i = 3; i >= 0; i--) tmp.push_back(seq_num[i*8 +: 8]);  // Sequence number
        for (i = 3; i >= 0; i--) tmp.push_back(ack_num[i*8 +: 8]);  // Ack number
        tmp.push_back(8'h50);           // Data offset (5*4=20 bytes) + reserved
        tmp.push_back(tcp_flags);       // Flags
        tmp.push_back(8'h20); tmp.push_back(8'h00); // Window size
        tmp.push_back(8'h00); tmp.push_back(8'h00); // Checksum (placeholder)
        tmp.push_back(8'h00); tmp.push_back(8'h00); // Urgent pointer

        // TCP payload
        for (i = 0; i < payload_len; i++) begin
            tmp.push_back(tcp_payload[i]);
        end

        // Ethernet CRC32 (placeholder)
        tmp.push_back(8'hDE); tmp.push_back(8'hAD);
        tmp.push_back(8'hBE); tmp.push_back(8'hEF);

        // Convert to array
        frame_bytes = new[tmp.size()];
        for (i = 0; i < tmp.size(); i++) begin
            frame_bytes[i] = tmp[i];
        end
    endtask

    // Task to send Ethernet frame via UART
    task send_ethernet_frame_via_uart(
        input byte tcp_payload[],
        input int payload_len,
        input string description = ""
    );
        automatic byte frame_bytes[];
        automatic logic [47:0] src_mac = 48'hAABBCCDDEEFF;
        automatic logic [47:0] dst_mac = 48'h112233445566;
        automatic logic [31:0] src_ip = 32'hC0A80101;  // 192.168.1.1
        automatic logic [31:0] dst_ip = 32'hC0A80102;  // 192.168.1.2
        automatic logic [15:0] src_port = 16'd12345;
        automatic logic [15:0] dst_port = 16'd80;
        automatic logic [31:0] seq_num = 32'h12345678;
        automatic logic [31:0] ack_num = 32'h87654321;
        automatic logic [7:0] tcp_flags = 8'h18; // PSH + ACK

        $display("[TB] Sending Ethernet frame via UART: %s (payload_len=%0d)", description, payload_len);

        build_ethernet_frame(
            tcp_payload, payload_len,
            src_mac, dst_mac, src_ip, dst_ip,
            src_port, dst_port, seq_num, ack_num, tcp_flags,
            frame_bytes
        );

        send_uart_packet(8'h10, frame_bytes, frame_bytes.size()); // PKT_TYPE_ETH_RX
    endtask

    // Task to send APP command via UART
    task send_app_command(input logic [15:0] cmd);
        automatic byte cmd_bytes[2];
        cmd_bytes[0] = cmd[15:8];
        cmd_bytes[1] = cmd[7:0];

        $display("[TB] Sending APP command: 0x%04h", cmd);
        send_uart_packet(8'h01, cmd_bytes, 2); // PKT_TYPE_APP_CMD
    endtask

    // Monitor UART TX output
    logic [7:0] uart_tx_byte;
    logic uart_tx_valid;
    integer tx_bit_count;
    logic [9:0] tx_shift_reg;
    logic tx_sampling;

    always_ff @(posedge clk) begin
        if (!rst_n) begin
            tx_bit_count <= 0;
            tx_sampling <= 0;
            uart_tx_valid <= 0;
            tx_activity_pulse <= 0;
        end else begin
            uart_tx_valid <= 0;
            tx_activity_pulse <= 0;

            if (!tx_sampling && !uart_tx) begin
                // Start bit detected
                tx_sampling <= 1;
                tx_bit_count <= 0;
                tx_shift_reg <= 10'h3FF;
            end else if (tx_sampling) begin
                if ((tx_bit_count % BAUD_PERIOD) == (BAUD_PERIOD/2)) begin
                    // Sample at middle of bit period
                    tx_shift_reg <= {uart_tx, tx_shift_reg[9:1]};
                    if (tx_bit_count >= 9 * BAUD_PERIOD) begin
                        // Complete byte received
                        uart_tx_byte <= tx_shift_reg[8:1];
                        uart_tx_valid <= 1;
                        tx_sampling <= 0;
                        tx_activity_pulse <= 1;
                        $display("[TB] Received UART TX byte: 0x%02h", tx_shift_reg[8:1]);
                    end
                end
                tx_bit_count <= tx_bit_count + 1;
            end
        end
    end

    // Capture UART TX packets
    always_ff @(posedge clk) begin
        if (uart_tx_valid) begin
            tx_frame_buffer.push_back(uart_tx_byte);
        end
    end

    // Main test sequence
    initial begin
        automatic byte test_payload[32];
        automatic int i;

        // Wait for reset completion
        wait(rst_n);
        repeat(100) @(posedge clk);

        $display("[TB] Test 1: Send APP CONNECT command");
        send_app_command(16'h0001); // CONNECT command
        repeat(5000) @(posedge clk);

        $display("[TB] Test 2: Send small TCP payload");
        for (i = 0; i < 16; i++) test_payload[i] = 8'h41 + i; // "ABCD..."
        send_ethernet_frame_via_uart(test_payload, 16, "Small HTTP request");
        repeat(10000) @(posedge clk);

        $display("[TB] Test 3: Send larger TCP payload");
        for (i = 0; i < 32; i++) test_payload[i] = 8'h30 + (i % 10); // "0123..."
        send_ethernet_frame_via_uart(test_payload, 32, "Larger data packet");
        repeat(15000) @(posedge clk);

        $display("[TB] Test 4: Send APP CLOSE command");
        send_app_command(16'h0002); // CLOSE command
        repeat(5000) @(posedge clk);

        $display("[TB] Tests completed. RX buffer: %0d bytes, TX buffer: %0d bytes",
                 rx_frame_buffer.size(), tx_frame_buffer.size());

        // Analyze received data
        if (tx_frame_buffer.size() > 0) begin
            $display("[TB] UART TX data received:");
            for (i = 0; i < tx_frame_buffer.size() && i < 64; i++) begin
                $write("0x%02h ", tx_frame_buffer[i]);
                if ((i % 16) == 15) $display("");
            end
            if ((i % 16) != 0) $display("");
        end else begin
            $display("[TB] No UART TX data received");
        end

        repeat(1000) @(posedge clk);
        $display("[TB] Simulation completed");
        $finish;
    end

endmodule
