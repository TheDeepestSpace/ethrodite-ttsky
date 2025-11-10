`timescale 1ns/1ps
`include "helper.c"

module eth_ipv4_tcp_tb;

  // -----------------------------
  // Parameters
  // -----------------------------
  parameter DATA_WIDTH = 8;

  // -----------------------------
  // Clock & Reset
  // -----------------------------
  logic clk = 0;
  logic rst_n = 0;
  always #5 clk = ~clk;

  initial begin
    rst_n = 0;
    #50;
    rst_n = 1;
  end

  // -----------------------------
  // AXI-Stream interfaces
  // -----------------------------
  axi_stream_if.master m_axis();
  axi_stream_if.slave  s_axis();

  // -----------------------------
  // DUT instantiation
  // -----------------------------
  my_eth_ipv4_tcp_dut #(
      .DATA_WIDTH(DATA_WIDTH)
  ) dut_inst (
      .clk(clk),
      .rst_n(rst_n),
      .s_axis(s_axis),
      .m_axis(m_axis)
  );

  // -----------------------------
  // Packet header struct
  // -----------------------------
  typedef struct packed {
      logic [47:0] eth_src;
      logic [47:0] eth_dst;
      logic [31:0] ip_src;
      logic [31:0] ip_dst;
      logic [15:0] tcp_src_port;
      logic [15:0] tcp_dst_port;
  } pkt_addrs_t;

  pkt_addrs_t pkt_addrs;

  initial begin
      // Example controlled addresses
      pkt_addrs.eth_src     = 48'h02_00_00_00_00_01;
      pkt_addrs.eth_dst     = 48'h02_00_00_00_00_02;
      pkt_addrs.ip_src      = 32'hC0A80001; // 192.168.0.1
      pkt_addrs.ip_dst      = 32'hC0A80002; // 192.168.0.2
      pkt_addrs.tcp_src_port= 16'd50000;
      pkt_addrs.tcp_dst_port= 16'd443;
  end

  // -----------------------------
  // DPI-C / socket interface
  // -----------------------------
  import "DPI-C" function void tb_connect(input string host, input int port);
  import "DPI-C" function void tb_recv(output byte data[]);
  import "DPI-C" function void tb_send(input byte data[], input int len);

  // -----------------------------
  // Packet driver task
  // -----------------------------
  task automatic send_packet(input byte payload[], input int len);
      byte frame[1500];
      int idx = 0;

      // --- Ethernet header ---
      frame[idx +:6] = pkt_addrs.eth_dst[47:0]; idx+=6;
      frame[idx +:6] = pkt_addrs.eth_src[47:0]; idx+=6;
      frame[idx +:2] = 16'h0800; // IPv4 EtherType
      idx +=2;

      // --- IPv4 header ---
      frame[idx +:4] = pkt_addrs.ip_src[31:0]; idx+=4;
      frame[idx +:4] = pkt_addrs.ip_dst[31:0]; idx+=4;
      // Other fields can be added (TTL, protocol, checksum)

      // --- TCP header ---
      frame[idx +:2] = pkt_addrs.tcp_src_port; idx+=2;
      frame[idx +:2] = pkt_addrs.tcp_dst_port; idx+=2;
      // Sequence, ACK, flags, window, checksum can be added

      // --- Payload ---
      for (int i=0; i<len; i++) frame[idx+i] = payload[i];
      int total_len = idx + len;

      // --- Drive AXI-Stream ---
      int beat_idx = 0;
      while (beat_idx < total_len) begin
          logic [63:0] tdata = 64'd0;
          logic [7:0]  tkeep = 8'hFF;
          int bytes_in_beat = (total_len - beat_idx >= AXI_BYTES) ? AXI_BYTES : total_len - beat_idx;

          for (int b=0; b<bytes_in_beat; b++)
              tdata[b*8 +:8] = frame[beat_idx + b];
          tkeep = (1 << bytes_in_beat) - 1;

          s_axis.tdata  <= tdata;
          s_axis.tkeep  <= tkeep;
          s_axis.tvalid <= 1;
          s_axis.tlast  <= (beat_idx + bytes_in_beat >= total_len);
          @(posedge clk);
          while (!s_axis.tready) @(posedge clk);

          beat_idx += bytes_in_beat;
      end
      s_axis.tvalid <= 0;
  endtask

  // -----------------------------
  // Live packet driver thread
  // -----------------------------
  initial begin
      tb_connect("127.0.0.1", 5000);
      byte payload[1460];
      while (1) begin
          tb_recv(payload);  // receive payload from Python bridge
          send_packet(payload, $size(payload));
      end
  end

  // -----------------------------
  // Optional: monitor AXI-Stream
  // -----------------------------
  always @(posedge clk) begin
      if (s_axis.tvalid && s_axis.tready) begin
          $display("AXI RX beat: tdata=%h tkeep=%b tlast=%b", s_axis.tdata, s_axis.tkeep, s_axis.tlast);
      end
  end

endmodule
