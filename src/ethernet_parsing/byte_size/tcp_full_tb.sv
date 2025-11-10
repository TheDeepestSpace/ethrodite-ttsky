`timescale 1ns/1ps
`include "axi_stream_if.sv"
`include "ethernet_info.svh"
`include "ethernet_ipv4_handler.sv"
`include "tcp_handler.sv"
`include "tcp_reorder_buffer.sv"
`include "tcp_brain.sv"
`include "crc32.sv"

module tcp_full_tb;

    parameter int DATA_WIDTH = `INPUTWIDTH;
    parameter int BYTES = `AXI_BYTES(DATA_WIDTH);

    // Clock & reset
    logic clk;
    logic rst_n;

    // AXI interfaces (TB will exercise `tcp_top` — we provide PHY input and capture reordered output)
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) tcp_in_if();    // s_payload_axis (incoming from PHY)
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) m_axis_if();    // output_axis (reordered output to application)
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) phy_axis_if();    // phy_axis (unused in TB)
    axi_stream_if #(.DATA_WIDTH(DATA_WIDTH)) s_app_if();     // s_app_axis (app -> sender payload)

    // DUT control signals for reorder buffer
    logic [31:0] seq_start;            // per-frame seq_start (driven by send_frame, for display only)
    logic [31:0] reorder_seq_base;       // seq_base fed to reorder buffer (driven by TB)
    logic        base_valid;
    logic [31:0] window_size;

    // --- tcp_brain / control interfaces ---
    axi_stream_if instruction_if();
    axi_stream_if response_if();

    // signals connected to tcp_brain
    logic               sender_start;
    tcp_packet_info_s   sender_info;
    logic               sender_busy;
    tcp_command_info    in_info;
    logic [31:0]        brain_seq_base;

    // Instantiate DUT chain: tcp -> reorder (we drive tcp_handler directly in this TB)

    // TCP handler metadata signals (forwarded to tcp_brain)
    logic        tcp_meta_valid;
    logic        tcp_meta_ready;
    logic [15:0] tcp_meta_src_port;
    logic [15:0] tcp_meta_dst_port;
    logic [31:0] tcp_meta_seq_num;
    logic [31:0] tcp_meta_ack_num;
    logic [7:0]  tcp_meta_flags;
    logic [15:0] tcp_meta_window_size;
    logic [31:0] tcp_meta_payload_len;
    logic        tcp_meta_checksum_ok;
    logic        tcp_meta_checksum_valid;
    logic [15:0] tcp_meta_pseudo_header;

    // Instantiate top-level DUT: tcp_top connects ethernet/ipv4/tcp/reorder/sender/brain
    tcp_top u_top (
        .clk            (clk),
        .rst_n          (rst_n),
        .instruction_axis(instruction_if),
        .output_axis    (m_axis_if),
        .phy_axis       (phy_axis_if),
        .response_axis  (response_if),
        .s_payload_axis (tcp_in_if),
        .s_app_axis     (s_app_if),
        .in_info        (in_info)
    );

    // --- NEW ---
    // Global state for ACK validation
    logic [31:0] dut_ack_num = 0; // Tracks highest ACK received from DUT

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
        automatic int total_len;
        automatic int i;
        automatic int idx;
        automatic int tmp_sum;
        automatic int chksum;
        automatic int exp_crc;
        automatic byte tmp[$]; // local builder
        automatic int hdr_off;
        begin
            tmp = {};
            // Ethernet header (14 bytes)
            // dst MAC
            for (i=0; i<6; i++) tmp.push_back((dst_mac >> (8*(i))) & 8'hFF);
            // src MAC
            for (i=0; i<6; i++) tmp.push_back((src_mac >> (8*(i))) & 8'hFF);
            // ethertype (IPv4 = 0x0800)
            tmp.push_back(8'h08); tmp.push_back(8'h00);

            // IPv4 header (20 bytes, IHL=5)
            ip_len = 20 + tcp_len; // header + tcp
            // Version/IHL
            tmp.push_back(8'h45);
            // DSCP/ECN
            tmp.push_back(8'h00);
            // Total length
            tmp.push_back((ip_len >> 8) & 8'hFF);
            tmp.push_back(ip_len & 8'hFF);
            // ID
            tmp.push_back(8'h00); tmp.push_back(8'h00);
            // Flags/Frag
            tmp.push_back(8'h40); tmp.push_back(8'h00);
            // TTL
            tmp.push_back(8'h40);
            // Protocol (TCP)
            tmp.push_back(`IPV4_TCP_PROTO);
            // Header checksum (zero for now)
            tmp.push_back(8'h00); tmp.push_back(8'h00);
            // src ip
            for (i=0; i<4; i++) tmp.push_back((src_ip >> (8*(i))) & 8'hFF);
            // dst ip
            for (i=0; i<4; i++) tmp.push_back((dst_ip >> (8*(i))) & 8'hFF);

            // compute IPv4 header checksum over the last 20 bytes appended
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

            // Compute CRC32 over header + payload (exclude CRC bytes)
            exp_crc = 32'hFFFFFFFF;
            for (idx = 0; idx < tmp.size(); idx++) begin
                exp_crc = crc(exp_crc, tmp[idx]);
            end
            // Append CRC bytes (big-endian)
            tmp.push_back((exp_crc >> 24) & 8'hFF);
            tmp.push_back((exp_crc >> 16) & 8'hFF);
            tmp.push_back((exp_crc >> 8)  & 8'hFF);
            tmp.push_back((exp_crc)       & 8'hFF);

            // return
            frame_len = tmp.size();
            frame_bytes = new[frame_len];
            for (int ii = 0; ii < frame_len; ii++) frame_bytes[ii] = tmp[ii];
        end
    endtask

    // Capture received payload bytes
    byte rx_buffer[$];

    // Frame descriptor used by the test (top-level typedef so it can be used in initial)
    typedef struct {
        byte bytes[$];
        int len;
        logic [31:0] seq_start;
    } frame_t;

    frame_t frames[$];

    // Simple connection state for handshake responder
    typedef struct {
        bit          connected;
        logic [31:0] client_ip;
        logic [31:0] server_ip;
        logic [15:0] client_port;
        logic [15:0] server_port;
        logic [31:0] client_isn;
        logic [31:0] server_isn;
    } conn_t;
    conn_t conn;

    // Buffer for PHY-transmitted frame capture
    byte phy_frame[$];

    // Activity/diagnostic counters
    logic [63:0] tick_count = 0;
    logic [63:0] last_activity = 0;
    // mailbox used to record activity timestamps from multiple processes
    mailbox activity_mbox = new();
    localparam int WATCHDOG_CYCLES = 100000; // watchdog threshold in clock cycles (~1e5)

    // Clock
    initial clk = 0;
    always #5 clk = ~clk;

    // Reset sequence
    initial begin
        rst_n = 0;
        // clear connection state and buffers while in reset
        conn.connected   = 0;
        conn.client_ip   = 32'h0;
        conn.server_ip   = 32'h0;
        conn.client_port = 16'h0;
        conn.server_port = 16'h0;
        conn.client_isn  = 32'h0;
        conn.server_isn  = 32'h0;
        phy_frame.delete();
        rx_buffer.delete();
        repeat (5) @(posedge clk);
        rst_n = 1;
        repeat (5) @(posedge clk);
    end

    // Capture m_axis output bytes
    always_ff @(posedge clk) begin
        if (m_axis_if.tvalid && m_axis_if.tready) begin
            rx_buffer.push_back(m_axis_if.tdata);
            // update activity and show brief progress (report timestamp to mailbox)
            activity_mbox.put(tick_count);
            // Avoid printing when zero (0 % 256 == 0) — print on first byte and
            // every 256 bytes thereafter to show progress without spamming.
            if (rx_buffer.size() == 1) begin
                $display("[TB] %0t: received first byte, total=%0d", $time, rx_buffer.size());
            end else if (rx_buffer.size() != 0 && rx_buffer.size() % 256 == 0) begin
                $display("[TB] %0t: received %0d bytes so far", $time, rx_buffer.size());
            end
        end
    end

    // Always accept frames transmitted by DUT to the PHY and capture them
    always_ff @(posedge clk) begin
        // be ready to accept PHY frames
        phy_axis_if.tready <= 1'b1;
        if (phy_axis_if.tvalid && phy_axis_if.tready) begin
            $display("Captured PHY TX beat: tdata=%0h tlast=%0b", phy_axis_if.tdata, phy_axis_if.tlast);
            // capture valid bytes
            phy_frame.push_back(phy_axis_if.tdata);
            // if this beat is last, process the frame (in a forked task)
            if (phy_axis_if.tlast) begin
                automatic byte captured[] = phy_frame;
                phy_frame.delete();
                // process in background so we don't block the main monitor
                fork
                    process_phy_frame(captured);
                join_none
            end
        end
    end

    // Global tick and heartbeat/watchdog
    always_ff @(posedge clk) begin
        automatic logic [63:0] tmp_ts;
        tick_count <= tick_count + 1;
        // drain activity mailbox and update last_activity to the newest timestamp
        while (activity_mbox.try_get(tmp_ts)) begin
            last_activity <= tmp_ts;
        end
        // heartbeat every 10k cycles
        /*if ((tick_count % 10000) == 0) begin
            $display("[TB] %0t HEARTBEAT: tick=%0d conn=%0b rx_bytes=%0d phy_pending=%0d instr_valid=%0b resp_valid=%0b phy_tx_valid=%0b m_axis_valid=%0b",
                $time, tick_count, conn.connected, rx_buffer.size(), phy_frame.size(), instruction_if.tvalid, response_if.tvalid, phy_axis_if.tvalid, m_axis_if.tvalid);
        end
        // watchdog
        if (tick_count > 0 && (tick_count - last_activity) > WATCHDOG_CYCLES) begin
            $display("[TB][WATCHDOG] No activity for %0d cycles at time %0t. Dumping key signals...", tick_count - last_activity, $time);
            $display("  instruction_if.tvalid=%0b instruction_if.tready=%0b response_if.tvalid=%0b response_if.tready=%0b", instruction_if.tvalid, instruction_if.tready, response_if.tvalid, response_if.tready);
            $display("  phy_axis_if.tvalid=%0b phy_axis_if.tready=%0b tcp_in_if.tvalid=%0b tcp_in_if.tready=%0b", phy_axis_if.tvalid, phy_axis_if.tready, tcp_in_if.tvalid, tcp_in_if.tready);
            $display("  m_axis_if.tvalid=%0b m_axis_if.tready=%0b rx_buffer=%0d", m_axis_if.tvalid, m_axis_if.tready, rx_buffer.size());
            // Internal DUT signals (helpful for debugging why tcp_in_if.tready is deasserted)
            // Access via hierarchical path to u_top
            $display("  u_top.seq_base=%0h u_top.base_valid=%0b u_top.window_size=%0h", u_top.seq_base, u_top.base_valid, u_top.window_size);
            $display("  u_top.tcp_meta_valid=%0b u_top.tcp_meta_seq_num=%0h u_top.tcp_meta_flags=%0h", u_top.tcp_meta_valid, u_top.tcp_meta_seq_num, u_top.tcp_meta_flags);
            $display("  u_top.eth_meta_valid=%0b u_top.eth_meta_protocol=%0h u_top.eth_meta_total_length=%0d u_top.eth_meta_crc32_ok=%0b", u_top.eth_meta_valid, u_top.eth_meta_protocol, u_top.eth_meta_total_length, u_top.eth_meta_crc32_ok);
            // extend last_activity so we don't spam
            last_activity <= tick_count;
        end*/
    end

    // Helper to read big-endian 16/32 from a byte array
    function automatic logic [31:0] read_u32(input byte a[], input int idx);
        logic [31:0] v;
        begin
            v = {a[idx], a[idx+1], a[idx+2], a[idx+3]};
            return v;
        end
    endfunction

    function automatic logic [15:0] read_u16(input byte a[], input int idx);
        logic [15:0] v;
        begin
            v = {a[idx], a[idx+1]};
            return v;
        end
    endfunction

    // Task to process frames emitted by DUT on the PHY and respond to SYNs
    // --- MODIFIED ---
    task automatic process_phy_frame(input byte frame[]);
        automatic int eth_off = 0;
        automatic int ip_off;
        automatic int ihl;
        automatic int tcp_off;
        automatic logic [31:0] src_ip, dst_ip;
        automatic logic [47:0] src_mac, dst_mac;
        automatic logic [15:0] src_port, dst_port;
        automatic logic [31:0] seq_num, ack_num;
        automatic byte flags_byte;
        automatic int i;
        automatic byte seg[];
        automatic int sl;
        automatic logic [15:0] pseudo_sum;
        automatic byte resp_frame[];
        automatic int resp_len;
        begin
            if (frame.size() < `ETH_HEADER_BYTES + `IPV4_HEADER_MIN_BYTES) return;
            // read MACs
            dst_mac = {frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]};
            src_mac = {frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]};
            ip_off = `ETH_HEADER_BYTES;
            ihl = frame[ip_off + `IPV4_VERSION_IHL_OFFSET] & 8'h0F;
            if (ihl < 5) ihl = 5;
            tcp_off = ip_off + ihl*4;
            if (tcp_off + `TCP_HEADER_MIN_LEN > frame.size()) return; // Check for truncated packet
            src_ip = read_u32(frame, ip_off + `IPV4_SRC_IP_OFFSET);
            dst_ip = read_u32(frame, ip_off + `IPV4_DST_IP_OFFSET);
            src_port = read_u16(frame, tcp_off + `TCP_SRC_PORT_BASE);
            dst_port = read_u16(frame, tcp_off + `TCP_DST_PORT_BASE);
            seq_num = read_u32(frame, tcp_off + `TCP_SEQ_NUM_BASE);
            ack_num = read_u32(frame, tcp_off + `TCP_ACK_NUM_BASE);
            flags_byte = frame[tcp_off + `TCP_FLAGS_BASE];

            // Detect SYN (without ACK) from DUT — it is attempting to open a connection
            if ((flags_byte & (1 << `TCP_FLAG_SYN)) && !(flags_byte & (1 << `TCP_FLAG_ACK))) begin
                // store client info
                conn.client_ip = src_ip;
                conn.server_ip = dst_ip;
                conn.client_port = src_port;
                conn.server_port = dst_port;
                conn.client_isn = seq_num;
                conn.server_isn = $urandom;
                $display("[TB] %0t: Detected SYN from %0h:%0d seq=%0h", $time, conn.client_ip, conn.client_port, conn.client_isn);

                // build SYN-ACK: src = server (dst of incoming), dst = client
                build_tcp_segment(
                    dst_ip, // src ip (server)
                    src_ip, // dst ip (client)
                    dst_port,
                    src_port,
                    conn.server_isn,
                    conn.client_isn + 1,
                    (1 << `TCP_FLAG_SYN) | (1 << `TCP_FLAG_ACK),
                    {}, 0,
                    seg, sl, pseudo_sum
                );

                // send from server MAC->client MAC (swap)
                build_eth_ipv4_tcp_frame(seg, sl, dst_mac, src_mac, dst_ip, src_ip, resp_frame, resp_len);
                // send it into DUT (incoming path)
                $display("[TB] %0t: Sending SYN-ACK from server_isn=%0h with ack_num=%0h to client", $time, conn.server_isn, conn.client_isn + 1);
                activity_mbox.put(tick_count);
                // Use server_isn as the seq_start for the SYN-ACK frame so
                // bookkeeping matches the sequence number carried in the TCP header.
                send_frame(resp_frame, resp_len, conn.server_isn); // seq_start set to server's seq
            end

            // Small debug to show what we parsed vs. what we expect
            //$display("[TB DEBUG] parsed seq=%0h ack=%0h flags=%02b expected_server_isn=%0h", seq_num, ack_num, flags_byte, conn.server_isn);

            // Detect ACK completing handshake (ACK for our server_isn)
            // This checks "ACK is set" AND "SYN is NOT set"
            if ((flags_byte & (1 << `TCP_FLAG_ACK)) && !(flags_byte & (1 << `TCP_FLAG_SYN))) begin
                $display("connected: %d, ack_num: %h, dut: %h", conn.connected, ack_num, dut_ack_num);
                // If ack_num matches server_isn + 1, handshake complete
                if (!conn.connected && ack_num == conn.server_isn + 1) begin
                    conn.connected = 1;
                    activity_mbox.put(tick_count);
                    $display("[TB] %0t: Handshake complete: client %0h:%0d <-> server %0h:%0d", $time, conn.client_ip, conn.client_port, conn.server_ip, conn.server_port);

                end else if (conn.connected && (ack_num > dut_ack_num) && (ack_num > (conn.server_isn + 1))) begin
                    // --- NEW ---
                    // Track the highest *data* ACK received from the DUT
                    // We only care about ACKs that acknowledge our data, which starts
                    // *after* our SYN (conn.server_isn + 1).
                    dut_ack_num = ack_num; // Use blocking assignment
                    $display("[TB] %0t: DUT acked data up to seq %0h (delta=%0d)",
                        $time, ack_num, ack_num - (conn.server_isn + 1));
                end else if (conn.connected && ((ack_num <= dut_ack_num) || dut_ack_num == 0)) begin
                    dut_ack_num = ack_num;
                    $display("[TB]: detected duplicate ACK");

                end else if (!conn.connected) begin
                    $display("[TB] %0t: ACK received but ack_num (%0h) != expected (%0h) and not connected", $time, ack_num, conn.server_isn + 1);
                end
            end
        end
    endtask

    // Send single AXI beat
    // Send one AXI beat into tcp_handler (tcp_in_if)
    task automatic send_word(
        input logic [DATA_WIDTH-1:0] tdata,
        input bit                    tlast
    );
        begin
            tcp_in_if.tdata  = tdata;
            tcp_in_if.tvalid = 1'b1;
            tcp_in_if.tlast  = tlast;
            // diagnostic: show what the TB is driving into the payload axis
            @(posedge clk);
            while (!tcp_in_if.tready) @(posedge clk);
            tcp_in_if.tvalid = 0;
            tcp_in_if.tlast  = 0;
            tcp_in_if.tdata  = '0;
        end
    endtask

    // Build TCP segment (starts at TCP header byte 0)
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
        automatic int tcp_start = 0;
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
            // window size (16'h1000) split into two bytes

            bytes[`TCP_WINDOW_SIZE_BASE + 0] = win[15:8];
            bytes[`TCP_WINDOW_SIZE_BASE + 1] = win[7:0];
            bytes[`TCP_CHECKSUM_BASE + 0] = 8'h00;
            bytes[`TCP_CHECKSUM_BASE + 1] = 8'h00;
            bytes[`TCP_URGENT_PTR_BASE + 0] = 8'h00;
            bytes[`TCP_URGENT_PTR_BASE + 1] = 8'h00;

            // payload
            for (int i=0; i<t_payload_len; i++)
                bytes[`TCP_HEADER_MIN_LEN + i] = t_payload_bytes[i];

            pkt_len = `TCP_HEADER_MIN_LEN + t_payload_len;

            // compute pseudo-header sum (src/dst IP + proto/length)
            sum = 0;
            sum += t_src_ip[31:16];
            sum += t_src_ip[15:0];
            sum += t_dst_ip[31:16];
            sum += t_dst_ip[15:0];
            sum += (`IPV4_TCP_PROTO<<8) + (t_payload_len + `TCP_HEADER_MIN_LEN);
            while (sum >> 16) sum = (sum & 16'hFFFF) + (sum >> 16);
            pseudo_header_sum = sum[15:0];

            // TCP checksum: pseudo header + tcp header (with zero checksum) + payload
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

    // Send full frame with seq_start
    task automatic send_frame(byte frame_bytes[], int len, logic [31:0] frame_seq);
        automatic logic [DATA_WIDTH-1:0] tdata;
        automatic int i, b;
        begin
            // This signal is not connected to the DUT, it's for TB bookkeeping/display only
            seq_start = frame_seq; 
            // mark activity and announce the transfer (report to mailbox)
            activity_mbox.put(tick_count);
            //$display("[TB] %0t: send_frame start seq=%0h len=%0d", $time, frame_seq, len);
            // diagnostic: dump first bytes of the frame we're about to send
            begin
                int dump_n = (len < 16) ? len : 16;
                string s = "";
                for (int di = 0; di < dump_n; di++) begin
                    $sformat(s, "%s %02x", s, frame_bytes[di]);
                end
                //$display("[TB FRAME DUMP] first %0d bytes:%s", dump_n, s);
            end
            @(posedge clk);

            for (i = 0; i < len; i += 1) begin
                tdata = frame_bytes[i][7:0];
                send_word(tdata, (i >= len));
            end
        end
    endtask

    // Main test
    // --- MODIFIED ---
    initial begin
        // local test variables (declare before any statements to satisfy SV rules)
        static byte message[$];
        static int message_len = 64;
        static int pos = 0;
        // --- MODIFIED --- Base seq is set *after* handshake now
        static logic [31:0] base_seq; 
        logic [31:0] expected_final_ack;

        @(posedge rst_n);
        m_axis_if.tready <= 1;
        tcp_in_if.tvalid <= 0;
        tcp_in_if.tlast  <= 0;

        $display("Starting full TCP reordering test...");

        // Create message
        for (int i=0; i<message_len; i++) begin
            message.push_back($urandom_range(0,255));
            $display("%0d is: %h", i, message[i]);
        end
        // --- MODIFIED --- Frame generation moved *after* handshake

        // Reset and prepare
        rst_n = 0; repeat (200) @(posedge clk);
        // default signals
        sender_busy = 1'b0; // assume sender is free for this test
        instruction_if.tvalid = 1'b0;
        instruction_if.tdata  = '0;
        instruction_if.tlast  = 1'b0;
        response_if.tready = 1'b1; // accept notifications from brain

        rst_n = 1; repeat (4096) @(posedge clk);

        // --- Initialize connection by sending CONNECT to tcp_brain ---
        // Fill in connection info (DUT's perspective)
        in_info.src_mac   = 48'hAABBCCDDEEFF; // DUT's MAC
        in_info.dst_mac   = 48'h112233445566; // Server's MAC
        in_info.src_ip    = 32'h0A000001; // 10.0.0.1 (DUT's IP)
        in_info.dst_ip    = 32'h0A000002; // 10.0.0.2 (Server's IP)
        in_info.src_port  = 16'd1234;     // DUT's Port
        in_info.dst_port  = 16'd80;       // Server's Port
        in_info.payload_len = 16'h0;
        in_info.tcp_checksum = 16'h0;

        // Send CMD_CONNECT (use low 16 bits of tdata)
        instruction_if.tdata  = 1; // CMD_CONNECT
        instruction_if.tvalid = 1'b1;
        instruction_if.tlast  = 1'b1;
        activity_mbox.put(tick_count);
        // wait until brain accepts instruction
        @(posedge clk);
        while (!instruction_if.tready) @(posedge clk);
        instruction_if.tvalid = 1'b0;
        instruction_if.tlast  = 1'b0;

        $display("CONNECT sent to tcp_brain, waiting for SYN response...");

        // Wait for brain to issue a response/notification (SYN sent)
        wait (response_if.tvalid == 1'b1);

        $display("SYN response received from tcp_brain.");

        // consume response
        @(posedge clk);
        // wait for the 3-way handshake to complete (conn.connected set by process_phy_frame)
        begin
            int wait_cycles = 0;
            while (!conn.connected && wait_cycles < 20000) begin
                @(posedge clk);
                wait_cycles += 1;
            end
            if (!conn.connected) begin
                $display("[TB] ERROR: handshake did not complete within %0d cycles (conn.connected=%0b)", wait_cycles, conn.connected);
                $stop(1);
            end else begin
                $display("[TB] Handshake complete before sending payloads (waited %0d cycles)", wait_cycles);
            end
        end
    
        // --- MODIFIED ---
        // Now that handshake is complete, we know the server ISN.
        // Re-base our data to start *after* the server's SYN.
        base_seq = conn.server_isn + 1;
        
        // Modify the frame generation to use the *actual* server ISN.
        frames.delete();
        pos = 0;
        // Re-generate frames starting at the correct sequence number
        while (pos < message_len) begin
            automatic frame_t f;
            automatic int flen = $urandom_range(32, 128);
            if (pos + flen > message_len) flen = message_len - pos;
            f.len = flen;
            f.bytes = {};
            for (int j=0; j<flen; j++) f.bytes.push_back(message[pos + j]);
            f.seq_start = base_seq + pos; // Use new base
            frames.push_back(f);
            pos += flen;
        end
        $display("[TB] Generated %0d frames starting at seq=%0h", frames.size(), base_seq);

        // Shuffle frames (out-of-order)
        $display("[TB] THERE ARE %d FRAMES", frames.size());
        for (int i = 0; i < frames.size(); i++) begin
            automatic int j = $urandom_range(0, frames.size()-1);
            automatic frame_t tmp = frames[i];
            frames[i] = frames[j];
            frames[j] = tmp;
        end
        $display("[TB] Shuffled %0d frames.", frames.size()); // Keep commented out per user request

        // send TCP segments (start at TCP header) with built headers
        for (int i=0; i<frames.size(); i++) begin
            // build a full frame for each payload
                automatic byte seg[];
                automatic int sl;
                automatic logic [15:0] pseudo_sum;
                automatic byte frame[];
                automatic int  flen;
                if (frames[i].len > 0)
                    $display("sending frame %0d/%0d: seq_start=%0d len=%0d", i+1, frames.size(), frames[i].seq_start, frames[i].len);

                // Use the established connection parameters from 'conn' and 'in_info'.
                build_tcp_segment(
                    conn.server_ip,   // src IP (server)
                    conn.client_ip,   // dst IP (client)
                    conn.server_port, // src Port (server)
                    conn.client_port, // dst Port (client)
                    frames[i].seq_start,   // <--- Correct sequence number
                    conn.client_isn + 1,   // Ack client's SYN
                    (1<<`TCP_FLAG_ACK) | (1<<`TCP_FLAG_PSH), // PSH/ACK
                    frames[i].bytes,
                    frames[i].len,
                    seg,
                    sl,
                    pseudo_sum
                );

                // Wrap into Ethernet+IPv4 frame and append CRC
                build_eth_ipv4_tcp_frame(seg, sl,
                    in_info.dst_mac, // src MAC (server)
                    in_info.src_mac, // dst MAC (client)
                    conn.server_ip,   // src IP (server)
                    conn.client_ip,   // dst IP (client)
                    frame, flen
                );

                // send full Ethernet frame into tcp_top.s_payload_axis
                // The frame_seq parameter here is just for display
                send_frame(frame, flen, frames[i].seq_start);
                repeat (500) @(posedge clk);
            // small gap between frames
            repeat($urandom_range(1,3)) @(posedge clk);
        end

        // Wait for pipeline to consume
        repeat (1000) @(posedge clk);

        // Validate output
        // --- NEW: Renamed to TEST 1 ---
        $display("[TB] --- Validating Data Integrity ---");
        if (rx_buffer.size() != message.size()) begin
            $display("TEST FAILED (Integrity): TOTAL SIZE MISMATCH: expected %0d got %0d", message.size(), rx_buffer.size());
        end else begin
            automatic bit match = 1;
            for (int i=0; i<message.size(); i++) begin
                if (rx_buffer[i] !== message[i]) begin
                    $display("TEST FAILED (Integrity): BYTE MISMATCH at %0d: expected %02x got %02x", i, message[i], rx_buffer[i]);
                    match = 0;
                end
            end
            if (match) $display("TEST PASS (Integrity): Reassembled payload matches original message (%0d bytes)", message_len);
        end

        // --- NEW: TEST 2: ACK Validation ---
        $display("[TB] --- Validating DUT Acknowledgments ---");
        // The DUT should have acked all data bytes. The final ACK should be
        // (server's starting seq) + (number of data bytes)
        expected_final_ack = base_seq + message_len;
        
        // Give some extra time for the last ACK to be processed
        repeat (500) @(posedge clk);
        
        if (dut_ack_num == expected_final_ack) begin
            $display("TEST PASS (ACKs): DUT acknowledged all data correctly (final ack=%0h)", dut_ack_num);
        end else begin
            $display("TEST FAILED (ACKs): DUT ACK MISMATCH: expected %0h got %0h", expected_final_ack, dut_ack_num);
        end

        $display("Test complete");
        $stop(0);
    end

endmodule