`timescale 1ns/1ps
// Includes from both testbenches
`include "ethernet_info.svh"

module tcp_full_tb;

    // -------------------------
    // Clock & Reset (from uart_tb.sv)
    // -------------------------
    logic clk;
    logic rst_n;

    initial begin
        clk = 0;
        forever #10 clk = ~clk;  // 50 MHz (20ns period)
    end

    initial begin
        rst_n = 0;
        #100;
        rst_n = 1;
    end

    // -------------------------
    // UART pins (from uart_tb.sv)
    // -------------------------
    logic uart_rx_pin;
    logic uart_tx_pin;

    // -------------------------
    // Instantiate final_top (from uart_tb.sv)
    // -------------------------
    final_top #(
        .DATA_WIDTH(8),
        .BAUD_RATE(115200),
        .CLK_FREQ(50000000)
    ) uut (
        .clk(clk),
        .rst_n(rst_n),
        .uart_rx(uart_rx_pin),
        .uart_tx(uart_tx_pin)
    );

    // -------------------------
    // UART parameters (from uart_tb.sv)
    // -------------------------
    localparam integer CLK_FREQ = 50000000;
    localparam integer BAUD_RATE = 115200;
    // Calculate bit period in nanoseconds for # delays
    localparam real T_CLK = 1_000_000_000.0 / CLK_FREQ; // Clock period in ns
    localparam real T_BIT = 1_000_000_000.0 / BAUD_RATE; // Bit period in ns
    localparam integer BIT_PERIOD_NS = T_BIT;
    localparam integer HALF_BIT_PERIOD_NS = T_BIT / 2.0;

    // -------------------------
    // Task: Send a byte over UART (from uart_tb.sv)
    // Uses real-time delays based on baud rate
    // -------------------------
    task automatic uart_send_byte(input logic [7:0] byte_in, input bit verbose = 0);
        integer i;
        begin
            if (verbose) $display("[TB->UART] %0t: Sending byte 0x%02h", $time, byte_in);

            // Start bit
            uart_rx_pin = 1'b0;
            #(BIT_PERIOD_NS);

            // Data bits LSB first
            for (i = 0; i < 8; i = i + 1) begin
                uart_rx_pin = byte_in[i];
                #(BIT_PERIOD_NS);
            end

            // Stop bit
            uart_rx_pin = 1'b1;
            #(BIT_PERIOD_NS);

            // ADDED: Ensure at least one bit-period of idle time
            // This gives the DUT's state machine time to process the byte.
            #(BIT_PERIOD_NS);

            if (verbose) $display("[TB->UART] %0t: Send complete 0x%02h", $time, byte_in);
        end
    endtask

    // -------------------------
    // Task: Receive a byte from UART (from uart_tb.sv)
    // Uses real-time delays based on baud rate
    // -------------------------
    task automatic uart_receive_byte(output logic [7:0] byte_out);
        integer i;
        begin
            byte_out = 0;

            // Wait for start bit
            @(negedge uart_tx_pin);
            // Sample in the middle of the start bit to align
            #(HALF_BIT_PERIOD_NS);

            // Data bits LSB first
            for (i = 0; i < 8; i = i + 1) begin
                #(BIT_PERIOD_NS);
                byte_out[i] = uart_tx_pin;
            end

            // Wait for Stop bit
            #(BIT_PERIOD_NS);

            $display("[UART->TB] %0t: Received byte 0x%02h", $time, byte_out);

            // Allow line to return to idle if necessary
            #(HALF_BIT_PERIOD_NS);
        end
    endtask

    // -------------------------
    // UART Packet Constants (from tcp_full_tb.sv)
    // -------------------------
    localparam logic [7:0] PARROT          = 8'd0;
    localparam logic [7:0] ETH_FRAME_IN    = 8'd1;
    localparam logic [7:0] ETH_FRAME_OUT   = 8'd2;
    localparam logic [7:0] REMAINING_LAYER = 8'd3;
    localparam logic [7:0] INSTRUCTION     = 8'd4;
    localparam logic [7:0] BRAIN_STATUS    = 8'd5;
    localparam logic [7:0] PAYLOAD         = 8'd6;
    localparam logic [7:0] INFO            = 8'd7;

    // -------------------------
    // Global State (from tcp_full_tb.sv)
    // -------------------------
    logic [31:0] dut_ack_num = 0;
    byte rx_buffer[$];

    typedef struct {
        byte bytes[$];
        int len;
        logic [31:0] seq_start;
    } frame_t;
    frame_t frames[$];

    typedef struct {
        bit  connected;
        logic [31:0] client_ip;
        logic [31:0] server_ip;
        logic [15:0] client_port;
        logic [15:0] server_port;
        logic [31:0] client_isn;
        logic [31:0] server_isn;
    } conn_t;
    conn_t conn;

    // -------------------------
    // Helper Tasks (from tcp_full_tb.sv)
    // These will now call the bit-banging uart_send_byte task
    // -------------------------

    // Send connection info via UART
    task automatic uart_send_conn_info(
        input logic [47:0] src_mac,
        input logic [47:0] dst_mac,
        input logic [31:0] src_ip,
        input logic [31:0] dst_ip,
        input logic [15:0] src_port,
        input logic [15:0] dst_port
    );
        begin
            $display("[TB] %0t: ========================================", $time);
            $display("[TB] %0t: Sending Connection Info via UART", $time);
            $display("[TB] %0t:   SRC MAC: %012h", $time, src_mac);
            $display("[TB] %0t:   DST MAC: %012h", $time, dst_mac);
            $display("[TB] %0t:   SRC IP:  %08h", $time, src_ip);
            $display("[TB] %0t:   DST IP:  %08h", $time, dst_ip);
            $display("[TB] %0t:   SRC PORT: %0d", $time, src_port);
            $display("[TB] %0t:   DST PORT: %0d", $time, dst_port);
            $display("[TB] %0t: ========================================", $time);

            // Send src_mac (6 bytes, indices 0-5)
            for (int i = 0; i < 6; i++) begin
                uart_send_byte(INFO);
                uart_send_byte(i);
                uart_send_byte(src_mac[47 - i*8 -: 8], 1); // verbose
            end

            // Send dst_mac (6 bytes, indices 6-11)
            for (int i = 0; i < 6; i++) begin
                uart_send_byte(INFO);
                uart_send_byte(6 + i);
                uart_send_byte(dst_mac[47 - i*8 -: 8], 1); // verbose
            end

            // Send src_ip (4 bytes, indices 12-15)
            for (int i = 0; i < 4; i++) begin
                uart_send_byte(INFO);
                uart_send_byte(12 + i);
                uart_send_byte(src_ip[31 - i*8 -: 8], 1); // verbose
            end

            // Send dst_ip (4 bytes, indices 16-19)
            for (int i = 0; i < 4; i++) begin
                uart_send_byte(INFO);
                uart_send_byte(16 + i);
                uart_send_byte(dst_ip[31 - i*8 -: 8], 1); // verbose
            end

            // Send src_port (2 bytes, indices 20-21)
            uart_send_byte(INFO);
            uart_send_byte(20);
            uart_send_byte(src_port[15:8], 1); // verbose

            uart_send_byte(INFO);
            uart_send_byte(21);
            uart_send_byte(src_port[7:0], 1); // verbose

            // Send dst_port (2 bytes, indices 22-23)
            uart_send_byte(INFO);
            uart_send_byte(22);
            uart_send_byte(dst_port[15:8], 1); // verbose

            uart_send_byte(INFO);
            uart_send_byte(23);
            uart_send_byte(dst_port[7:0], 1); // verbose

            $display("[TB] %0t: Connection info sent successfully", $time);
        end
    endtask

    // Send instruction via UART
    task automatic uart_send_instruction(input logic [7:0] cmd);
        begin
            $display("[TB] %0t: ========================================", $time);
            $display("[TB] %0t: Sending INSTRUCTION via UART", $time);
            $display("[TB] %0t:   Command: %0d", $time, cmd);
            $display("[TB] %0t: ========================================", $time);
            uart_send_byte(INSTRUCTION, 1);
            uart_send_byte(cmd, 1);
            $display("[TB] %0t: Instruction sent successfully (2 bytes)", $time);
        end
    endtask

    // Send Ethernet frame via UART
    task automatic uart_send_eth_frame(input byte frame[], input int len);
        begin
            string header_preview = "";
            int preview_len = (len < 32) ? len : 32;

            $display("[TB] %0t: ========================================", $time);
            $display("[TB] %0t: Sending ETHERNET FRAME via UART", $time);
            $display("[TB] %0t:   Total Length: %0d bytes", $time, len);

            for (int i = 0; i < preview_len; i++) begin
                $sformat(header_preview, "%s %02h", header_preview, frame[i]);
            end
            $display("[TB] %0t:   Preview (first %0d bytes):%s%s", $time, preview_len, header_preview,
                     (len > preview_len) ? "..." : "");
            $display("[TB] %0t: ========================================", $time);

            for (int i = 0; i < len; i++) begin
                uart_send_byte(ETH_FRAME_IN, 1);
                uart_send_byte(frame[i], 0); // verbose=0 to avoid spam
                if ((i > 0) && (i % 64 == 0)) begin
                    $display("[TB] %0t:   Progress: %0d/%0d bytes sent", $time, i, len);
                end
            end
            $display("[TB] %0t: Ethernet frame sent successfully (%0d total bytes)", $time, len * 2);
        end
    endtask

    // Helper: build complete Ethernet+IPv4+TCP frame and append CRC32
    task automatic build_eth_ipv4_tcp_frame(
        input byte tcp_seg[],
        input int  tcp_len,
        input logic [47:0] src_mac,
        input logic [47:0] dst_mac,
        input logic [31:0] src_ip,
        input logic [31:0] dst_ip,
        output byte frame_bytes[],
        output int  frame_len
    );
        automatic int off;
        automatic int ip_len;
        automatic int i;
        automatic int chksum;
        automatic int exp_crc;
        automatic byte tmp[$];
        automatic int hdr_off;
        begin
            tmp = {};
            // Ethernet header (14 bytes)
            for (i=0; i<6; i++) tmp.push_back((dst_mac >> (8*(5-i))) & 8'hFF);
            for (i=0; i<6; i++) tmp.push_back((src_mac >> (8*(5-i))) & 8'hFF);
            tmp.push_back(8'h08); tmp.push_back(8'h00);

            // IPv4 header (20 bytes, IHL=5)
            ip_len = 20 + tcp_len;
            tmp.push_back(8'h45);
            tmp.push_back(8'h00);
            tmp.push_back((ip_len >> 8) & 8'hFF);
            tmp.push_back(ip_len & 8'hFF);
            tmp.push_back(8'h00); tmp.push_back(8'h00);
            tmp.push_back(8'h40); tmp.push_back(8'h00);
            tmp.push_back(8'h40);
            tmp.push_back(`IPV4_TCP_PROTO);
            tmp.push_back(8'h00); tmp.push_back(8'h00);
            for (i=0; i<4; i++) tmp.push_back((src_ip >> (8*(3-i))) & 8'hFF);
            for (i=0; i<4; i++) tmp.push_back((dst_ip >> (8*(3-i))) & 8'hFF);

            // Compute IPv4 header checksum
            chksum = 0;
            hdr_off = tmp.size() - 20;
            for (i=0; i<20; i+=2) begin
                chksum += (tmp[hdr_off + i] << 8) + tmp[hdr_off + i + 1];
            end
            while (chksum >> 16) chksum = (chksum & 16'hFFFF) + (chksum >> 16);
            chksum = ~chksum & 16'hFFFF;
            tmp[hdr_off + 10] = (chksum >> 8) & 8'hFF;
            tmp[hdr_off + 11] = chksum & 8'hFF;

            // TCP segment payload
            for (i=0; i < tcp_len; i++) tmp.push_back(tcp_seg[i]);

            // Compute CRC32
            exp_crc = 32'hFFFFFFFF;
            for (int idx = 0; idx < tmp.size(); idx++) begin
                exp_crc = crc(exp_crc, tmp[idx]);
            end
            tmp.push_back((exp_crc >> 24) & 8'hFF);
            tmp.push_back((exp_crc >> 16) & 8'hFF);
            tmp.push_back((exp_crc >> 8)  & 8'hFF);
            tmp.push_back((exp_crc)       & 8'hFF);

            frame_len = tmp.size();
            frame_bytes = new[frame_len];
            for (int ii = 0; ii < frame_len; ii++) frame_bytes[ii] = tmp[ii];
        end
    endtask

    // Helper to read big-endian 16/32 from byte array
    function automatic logic [31:0] read_u32(input byte a[], input int idx);
        return {a[idx], a[idx+1], a[idx+2], a[idx+3]};
    endfunction

    function automatic logic [15:0] read_u16(input byte a[], input int idx);
        return {a[idx], a[idx+1]};
    endfunction

    // Build TCP segment
    task automatic build_tcp_segment(
        input  logic [31:0] t_src_ip,
        input  logic [31:0] t_dst_ip,
        input  logic [15:0] t_src_port,
        input  logic [15:0] t_dst_port,
        input  logic [31:0] t_seq_num,
        input  logic [31:0] t_ack_num,
        input  logic [7:0]  t_flags,
        input  byte         t_payload_bytes[],
        input  int          t_payload_len,
        output byte         seg_bytes[],
        output int          seg_len,
        output logic [15:0] pseudo_header_sum
    );
        automatic byte bytes[0:4095];
        automatic int pkt_len;
        automatic int sum;
        automatic int payload_sum;
        logic [15:0] win = 16'h1000;
        begin
            // TCP header
            bytes[`TCP_SRC_PORT_BASE + 0] = t_src_port[15:8];
            bytes[`TCP_SRC_PORT_BASE + 1] = t_src_port[7:0];
            bytes[`TCP_DST_PORT_BASE + 0] = t_dst_port[15:8];
            bytes[`TCP_DST_PORT_BASE + 1] = t_dst_port[7:0];
            for (int i=0; i<4; i++)
                bytes[`TCP_SEQ_NUM_BASE + i] = t_seq_num[31-8*i -: 8];
            for (int i=0; i<4; i++)
                bytes[`TCP_ACK_NUM_BASE + i] = t_ack_num[31-8*i -: 8];
            bytes[`TCP_DATA_OFFSET_BASE] = 8'h50;
            bytes[`TCP_FLAGS_BASE] = t_flags;
            bytes[`TCP_WINDOW_SIZE_BASE + 0] = win[15:8];
            bytes[`TCP_WINDOW_SIZE_BASE + 1] = win[7:0];
            bytes[`TCP_CHECKSUM_BASE + 0] = 8'h00;
            bytes[`TCP_CHECKSUM_BASE + 1] = 8'h00;
            bytes[`TCP_URGENT_PTR_BASE + 0] = 8'h00;
            bytes[`TCP_URGENT_PTR_BASE + 1] = 8'h00;

            // Payload
            for (int i=0; i<t_payload_len; i++)
                bytes[`TCP_HEADER_MIN_LEN + i] = t_payload_bytes[i];

            pkt_len = `TCP_HEADER_MIN_LEN + t_payload_len;

            // Pseudo-header sum
            sum = 0;
            sum += t_src_ip[31:16];
            sum += t_src_ip[15:0];
            sum += t_dst_ip[31:16];
            sum += t_dst_ip[15:0];
            sum += (`IPV4_TCP_PROTO<<8) + (t_payload_len + `TCP_HEADER_MIN_LEN);
            while (sum >> 16) sum = (sum & 16'hFFFF) + (sum >> 16);
            pseudo_header_sum = sum[15:0];

            // TCP checksum
            sum = pseudo_header_sum;
            payload_sum = 0;
            for (int i = 0; i < `TCP_HEADER_MIN_LEN; i += 2) begin
                if (i+1 >= `TCP_HEADER_MIN_LEN)
                    sum += {bytes[i], 8'h00};
                else
                    sum += {bytes[i], bytes[i+1]};
            end
            for (int i=0; i<t_payload_len; i+=2) begin
                if (i+1 >= t_payload_len)
                    payload_sum += {t_payload_bytes[i], 8'h00};
                else
                    payload_sum += {t_payload_bytes[i], t_payload_bytes[i+1]};
            end
            sum += payload_sum;
            while (sum >> 16) sum = (sum & 16'hFFFF) + (sum >> 16);
            sum = ~sum;
            bytes[`TCP_CHECKSUM_BASE + 0] = sum[15:8];
            bytes[`TCP_CHECKSUM_BASE + 1] = sum[7:0];

            seg_len = pkt_len;
            seg_bytes = new[seg_len];
            for (int i=0; i<seg_len; i++) seg_bytes[i] = bytes[i];
        end
    endtask

    // Background task to collect UART output and parse TCP frames
    task automatic uart_output_monitor();
        automatic byte eth_frame_buffer[$];
        automatic byte app_data_buffer[$];
        automatic logic [7:0] rx_byte;
        automatic logic [7:0] expected_header = 8'hFF;
        automatic int frame_count = 0;
        automatic bit waiting_for_data = 0;

        forever begin
            // This now calls the bit-banging receive task
            uart_receive_byte(rx_byte);

            if (!waiting_for_data) begin
                expected_header = rx_byte;
                waiting_for_data = 1;
                $display("[TB] %0t: Received header: 0x%02h (%s)", $time, rx_byte,
                         (rx_byte == ETH_FRAME_OUT) ? "ETH_FRAME_OUT" :
                         (rx_byte == REMAINING_LAYER) ? "REMAINING_LAYER" :
                         (rx_byte == BRAIN_STATUS) ? "BRAIN_STATUS" :
                         (rx_byte == PARROT) ? "PARROT" : "UNKNOWN");
            end else begin
                waiting_for_data = 0;

                case (expected_header)
                    ETH_FRAME_OUT: begin
                        eth_frame_buffer.push_back(rx_byte);

                        // Minimum frame: 14 (Eth) + 20 (IP) + 20 (TCP) + 4 (CRC) = 58 bytes
                        if (eth_frame_buffer.size() >= 58) begin
                            automatic byte frame_copy[];
                            frame_copy = new[eth_frame_buffer.size()];
                            for (int i = 0; i < eth_frame_buffer.size(); i++)
                                frame_copy[i] = eth_frame_buffer[i];

                            $display("[TB] %0t: ========================================", $time);
                            $display("[TB] %0t: Complete Ethernet frame received (#%0d)", $time, frame_count);
                            $display("[TB] %0t:   Frame size: %0d bytes", $time, eth_frame_buffer.size());
                            $display("[TB] %0t: ========================================", $time);

                            fork
                                process_phy_frame(frame_copy, frame_count);
                            join_none

                            frame_count++;
                            eth_frame_buffer.delete();
                        end
                    end

                    REMAINING_LAYER: begin
                        app_data_buffer.push_back(rx_byte);
                        rx_buffer.push_back(rx_byte);

                        if (rx_buffer.size() == 1) begin
                            $display("[TB] %0t: Received first application data byte", $time);
                        end else if (rx_buffer.size() % 256 == 0) begin
                            $display("[TB] %0t: Received %0d application bytes so far", $time, rx_buffer.size());
                        end
                    end

                    BRAIN_STATUS: begin
                        $display("[TB] %0t: BRAIN_STATUS data: 0x%02h", $time, rx_byte);
                    end

                    PARROT: begin
                        $display("[TB] %0t: PARROT echo: 0x%02h", $time, rx_byte);
                    end

                    default: begin
                        $display("[TB] %0t: WARNING: Data byte for unknown header 0x%02h", $time, expected_header);
                    end
                endcase
            end
        end
    endtask

    // Process frames from DUT (SYN responses, ACKs, etc.)
    task automatic process_phy_frame(input byte frame[], input int frame_num);
        automatic int eth_off = 0;
        automatic int ip_off;
        automatic int ihl;
        automatic int tcp_off;
        automatic logic [31:0] src_ip, dst_ip;
        automatic logic [47:0] src_mac, dst_mac;
        automatic logic [15:0] src_port, dst_port;
        automatic logic [31:0] seq_num, ack_num;
        automatic byte flags_byte;
        automatic byte seg[];
        automatic int sl;
        automatic logic [15:0] pseudo_sum;
        automatic byte resp_frame[];
        automatic int resp_len;
        automatic string flags_str = "";
        begin
            $display("[TB] %0t: ----------------------------------------", $time);
            $display("[TB] %0t: Processing received frame #%0d (%0d bytes)", $time, frame_num, frame.size());

            if (frame.size() < `ETH_HEADER_BYTES + `IPV4_HEADER_MIN_BYTES) begin
                $display("[TB] %0t: ERROR: Frame too small (%0d bytes)", $time, frame.size());
                return;
            end

            dst_mac = {frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]};
            src_mac = {frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]};
            $display("[TB] %0t:   Ethernet: SRC=%012h DST=%012h", $time, src_mac, dst_mac);

            ip_off = `ETH_HEADER_BYTES;
            ihl = frame[ip_off + `IPV4_VERSION_IHL_OFFSET] & 8'h0F;
            if (ihl < 5) ihl = 5;
            tcp_off = ip_off + ihl*4;
            if (tcp_off + `TCP_HEADER_MIN_LEN > frame.size()) begin
                $display("[TB] %0t: ERROR: TCP header truncated", $time);
                return;
            end

            src_ip = read_u32(frame, ip_off + `IPV4_SRC_IP_OFFSET);
            dst_ip = read_u32(frame, ip_off + `IPV4_DST_IP_OFFSET);
            $display("[TB] %0t:   IPv4: SRC=%08h DST=%08h", $time, src_ip, dst_ip);

            src_port = read_u16(frame, tcp_off + `TCP_SRC_PORT_BASE);
            dst_port = read_u16(frame, tcp_off + `TCP_DST_PORT_BASE);
            seq_num = read_u32(frame, tcp_off + `TCP_SEQ_NUM_BASE);
            ack_num = read_u32(frame, tcp_off + `TCP_ACK_NUM_BASE);
            flags_byte = frame[tcp_off + `TCP_FLAGS_BASE];

            if (flags_byte & (1 << `TCP_FLAG_SYN)) flags_str = {flags_str, "SYN "};
            if (flags_byte & (1 << `TCP_FLAG_ACK)) flags_str = {flags_str, "ACK "};
            if (flags_byte & (1 << `TCP_FLAG_FIN)) flags_str = {flags_str, "FIN "};
            if (flags_byte & (1 << `TCP_FLAG_RST)) flags_str = {flags_str, "RST "};
            if (flags_byte & (1 << `TCP_FLAG_PSH)) flags_str = {flags_str, "PSH "};

            $display("[TB] %0t:   TCP: SRC_PORT=%0d DST_PORT=%0d", $time, src_port, dst_port);
            $display("[TB] %0t:   TCP: SEQ=%08h ACK=%08h FLAGS=%s", $time, seq_num, ack_num, flags_str);

            // Detect SYN from DUT
            if ((flags_byte & (1 << `TCP_FLAG_SYN)) && !(flags_byte & (1 << `TCP_FLAG_ACK))) begin
                conn.client_ip = src_ip;
                conn.server_ip = dst_ip;
                conn.client_port = src_port;
                conn.server_port = dst_port;
                conn.client_isn = seq_num;
                conn.server_isn = $urandom;
                $display("[TB] %0t: >>> DETECTED SYN FROM DUT <<<", $time);
                $display("[TB] %0t:   Client ISN: %08h", $time, conn.client_isn);
                $display("[TB] %0t:   Server ISN: %08h (generated)", $time, conn.server_isn);

                // Build SYN-ACK
                $display("[TB] %0t: Building SYN-ACK response...", $time);
                build_tcp_segment(
                    dst_ip, src_ip, dst_port, src_port,
                    conn.server_isn, conn.client_isn + 1,
                    (1 << `TCP_FLAG_SYN) | (1 << `TCP_FLAG_ACK),
                    {}, 0, seg, sl, pseudo_sum
                );

                build_eth_ipv4_tcp_frame(seg, sl, dst_mac, src_mac, dst_ip, src_ip,
                                         resp_frame, resp_len);
                $display("[TB] %0t: Sending SYN-ACK via UART (%0d bytes)...", $time, resp_len);
                // This now calls the bit-banging send task
                uart_send_eth_frame(resp_frame, resp_len);
            end

            // Detect ACK completing handshake
            if ((flags_byte & (1 << `TCP_FLAG_ACK)) && !(flags_byte & (1 << `TCP_FLAG_SYN))) begin
                if (!conn.connected && ack_num == conn.server_isn + 1) begin
                    conn.connected = 1;
                    $display("[TB] %0t: >>> HANDSHAKE COMPLETE <<<", $time);
                    $display("[TB] %0t:   Connection established!", $time);
                end else if (conn.connected && ack_num > dut_ack_num) begin
                    dut_ack_num = ack_num;
                    $display("[TB] %0t: >>> DATA ACK RECEIVED <<<", $time);
                    $display("[TB] %0t:   DUT acknowledged up to SEQ=%08h", $time, ack_num);
                    $display("[TB] %0t:   Data bytes acknowledged: %0d", $time, ack_num - (conn.server_isn + 1));
                end
            end
            $display("[TB] %0t: ----------------------------------------", $time);
        end
    endtask

    // -------------------------
    // Main Test (from tcp_full_tb.sv)
    // -------------------------
    initial begin
        static byte message[$];
        static int message_len = 64;
        static int pos = 0;
        static logic [31:0] base_seq;
        logic [31:0] expected_final_ack;

        // Initialize UART line to idle high
        @(posedge rst_n);
        uart_rx_pin = 1'b1;
        $display("[%0t] TB: Reset released, UART line idle high.", $time);

        $display("Starting UART-based TCP test...");

        // Start output monitor in background
        fork
            uart_output_monitor();
        join_none

        // Create message
        for (int i=0; i<message_len; i++) begin
            message.push_back($urandom_range(0,255));
        end

        // Wait a bit
        #(100 * BIT_PERIOD_NS);

        // Send connection info via UART
        uart_send_conn_info(
            48'hAABBCCDDEEFF,  // src_mac (DUT)
            48'h112233445566,  // dst_mac (Server)
            32'h0A000001,      // src_ip (DUT)
            32'h0A000002,      // dst_ip (Server)
            16'd1234,          // src_port
            16'd80             // dst_port
        );

        #(100 * BIT_PERIOD_NS);

        // Send CONNECT instruction
        uart_send_instruction(1); // CMD_CONNECT

        $display("[TB] Waiting for handshake to complete...");

        // Wait for handshake
        begin
            int wait_cycles = 0;
            while (!conn.connected && wait_cycles < 50000) begin
                @(posedge clk);
                wait_cycles += 1;
            end
            if (!conn.connected) begin
                $display("[TB] ERROR: Handshake did not complete");
                $stop(1);
            end
        end

        // Generate frames based on actual server ISN
        base_seq = conn.server_isn + 1;
        frames.delete();
        pos = 0;
        while (pos < message_len) begin
            automatic frame_t f;
            automatic int flen = $urandom_range(32, 128);
            if (pos + flen > message_len) flen = message_len - pos;
            f.len = flen;
            f.bytes = {};
            for (int j=0; j<flen; j++) f.bytes.push_back(message[pos + j]);
            f.seq_start = base_seq + pos;
            frames.push_back(f);
            pos += flen;
        end

        // Shuffle frames
        for (int i = 0; i < frames.size(); i++) begin
            automatic int j = $urandom_range(0, frames.size()-1);
            automatic frame_t tmp = frames[i];
            frames[i] = frames[j];
            frames[j] = tmp;
        end

        $display("[TB] Sending %0d shuffled frames via UART...", frames.size());

        // Send frames via UART
        for (int i=0; i<frames.size(); i++) begin
            automatic byte seg[];
            automatic int sl;
            automatic logic [15:0] pseudo_sum;
            automatic byte frame[];
            automatic int flen;

            $display("[TB] %0t: ========================================", $time);
            $display("[TB] %0t: Preparing to send frame %0d/%0d", $time, i+1, frames.size());
            $display("[TB] %0t:   Sequence number: %08h", $time, frames[i].seq_start);
            $display("[TB] %0t:   Payload length: %0d bytes", $time, frames[i].len);
            $display("[TB] %0t: ========================================", $time);

            build_tcp_segment(
                conn.server_ip, conn.client_ip,
                conn.server_port, conn.client_port,
                frames[i].seq_start, conn.client_isn + 1,
                (1<<`TCP_FLAG_ACK) | (1<<`TCP_FLAG_PSH),
                frames[i].bytes, frames[i].len,
                seg, sl, pseudo_sum
            );

            build_eth_ipv4_tcp_frame(seg, sl,
                48'h112233445566, 48'hAABBCCDDEEFF,
                conn.server_ip, conn.client_ip,
                frame, flen
            );

            uart_send_eth_frame(frame, flen);
            $display("[TB] %0t: Frame %0d/%0d sent successfully", $time, i+1, frames.size());
            #(100 * BIT_PERIOD_NS);
        end

        #(5000 * BIT_PERIOD_NS);

        // Validate
        $display("[TB] --- Test Complete ---");
        $display("[TB] Final DUT ACK: %0h (expected: %0h)",
                 dut_ack_num, base_seq + message_len);

        $stop(0);
    end

endmodule
