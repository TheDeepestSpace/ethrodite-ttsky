// uart_tcp_mux.sv
`include "ethernet_info.svh"

module uart_tcp_mux #(
    parameter int DATA_WIDTH = 8
) (
    input logic clk,
    input logic rst_n,

    // Physical UART - slave (input)
    input  logic [DATA_WIDTH-1:0] uart_in_tdata,
    input  logic                  uart_in_tvalid,
    output logic                  uart_in_tready,
    input  logic                  uart_in_tlast,
    
    // AXI4-Stream master (commands to brain)
    output logic [DATA_WIDTH-1:0] instructions_to_brain_axis_tdata,
    output logic                  instructions_to_brain_axis_tvalid,
    input  logic                  instructions_to_brain_axis_tready,
    output logic                  instructions_to_brain_axis_tlast,
    
    // AXI4-Stream master (ethernet payload)
    output logic [DATA_WIDTH-1:0] eth_payload_axis_tdata,
    output logic                  eth_payload_axis_tvalid,
    input  logic                  eth_payload_axis_tready,
    output logic                  eth_payload_axis_tlast,
    
    // AXI4-Stream master (payload to be sent)
    output logic [DATA_WIDTH-1:0] payload_to_be_sent_axis_tdata,
    output logic                  payload_to_be_sent_axis_tvalid,
    input  logic                  payload_to_be_sent_axis_tready,
    output logic                  payload_to_be_sent_axis_tlast,
    
    // Connection info (latched on instruction) - flattened for Yosys compatibility
    output logic [47:0] out_info_src_mac,
    output logic [47:0] out_info_dst_mac,
    output logic [31:0] out_info_src_ip,
    output logic [31:0] out_info_dst_ip,
    output logic [15:0] out_info_src_port,
    output logic [15:0] out_info_dst_port,
    output logic [15:0] out_info_payload_len,
    output logic [15:0] out_info_tcp_checksum,

    // UART output - master
    output logic [DATA_WIDTH-1:0] uart_out_tdata,
    output logic                  uart_out_tvalid,
    input  logic                  uart_out_tready,
    output logic                  uart_out_tlast,
    
    // Rest of frame - slave (input)
    input  logic [DATA_WIDTH-1:0] rest_of_frame_axis_tdata,
    input  logic                  rest_of_frame_axis_tvalid,
    output logic                  rest_of_frame_axis_tready,
    input  logic                  rest_of_frame_axis_tlast,
    
    // Ethernet PHY - slave (input)
    input  logic [DATA_WIDTH-1:0] eth_phy_axis_tdata,
    input  logic                  eth_phy_axis_tvalid,
    output logic                  eth_phy_axis_tready,
    input  logic                  eth_phy_axis_tlast,
    
    // App response - slave (input)
    input  logic [DATA_WIDTH-1:0] app_response_axis_tdata,
    input  logic                  app_response_axis_tvalid,
    output logic                  app_response_axis_tready,
    input  logic                  app_response_axis_tlast
);

  // Internal signals for combinational logic
  logic [DATA_WIDTH-1:0] instructions_to_brain_tdata_i;
  logic                  instructions_to_brain_tvalid_i;
  logic [DATA_WIDTH-1:0] eth_payload_tdata_i;
  logic                  eth_payload_tvalid_i;
  logic [DATA_WIDTH-1:0] payload_to_be_sent_tdata_i;
  logic                  payload_to_be_sent_tvalid_i;
  logic [DATA_WIDTH-1:0] uart_out_tdata_i;
  logic                  uart_out_tvalid_i;
  logic                  uart_in_tready_i;
  logic                  rest_of_frame_tready_i;
  logic                  eth_phy_tready_i;
  logic                  app_response_tready_i;

  // Connect internal signals to outputs
  assign instructions_to_brain_axis_tdata = instructions_to_brain_tdata_i;
  assign instructions_to_brain_axis_tvalid = instructions_to_brain_tvalid_i;
  assign eth_payload_axis_tdata = eth_payload_tdata_i;
  assign eth_payload_axis_tvalid = eth_payload_tvalid_i;
  assign payload_to_be_sent_axis_tdata = payload_to_be_sent_tdata_i;
  assign payload_to_be_sent_axis_tvalid = payload_to_be_sent_tvalid_i;
  assign uart_out_tdata = uart_out_tdata_i;
  assign uart_out_tvalid = uart_out_tvalid_i;
  assign uart_in_tready = uart_in_tready_i;
  assign rest_of_frame_axis_tready = rest_of_frame_tready_i;
  assign eth_phy_axis_tready = eth_phy_tready_i;
  assign app_response_axis_tready = app_response_tready_i;

  // Packet type constants
  localparam PARROT = 8'd0;  // send back what we sent them
  localparam ETH_FRAME_IN = 8'd1;
  localparam ETH_FRAME_OUT = 8'd2;
  localparam REMAINING_LAYER = 8'd3;
  localparam INSTRUCTION = 8'd4;
  localparam BRAIN_STATUS = 8'd5;
  localparam PAYLOAD_COMING = 8'd6;
  localparam INFO = 8'd7;

  // UART byte interface
  logic [7:0] uart_rx_data, uart_tx_data, uart_extra_data, uart_header;
  logic uart_rx_valid, uart_tx_valid;
  logic uart_rx_ready, uart_tx_ready;

  // State machine states (using localparam instead of enum for Yosys compatibility)
  localparam S_POLL_UART         = 4'd0;
  localparam S_SEND_TO_BRAIN     = 4'd1;
  localparam S_SEND_TO_ETH       = 4'd2;
  localparam S_SEND_TO_TCP_SENDER = 4'd3;
  localparam S_LOAD_INFO         = 4'd4;
  localparam S_SEND_TO_UART      = 4'd5;
  localparam S_POLL_TCP_OUTPUT   = 4'd6;
  localparam S_POLL_FRAMES_OUT   = 4'd7;
  localparam S_POLL_BRAIN_STATUS = 4'd8;
  localparam S_GET_DATA          = 4'd9;
  localparam S_GET_BYTE          = 4'd10;
  localparam S_SEND_HEADER       = 4'd11;
  
  logic [3:0] state_r, state_n;

  always_comb begin
    //all same data for UART --> REST OF CHIP
    instructions_to_brain_tdata_i = uart_rx_data;
    eth_payload_tdata_i = uart_rx_data;
    payload_to_be_sent_tdata_i = uart_rx_data;
    uart_out_tdata_i = (state_r == S_SEND_HEADER) ? uart_header : uart_tx_data;

    //valid if in outputting state
    instructions_to_brain_tvalid_i = (state_r == S_SEND_TO_BRAIN);
    eth_payload_tvalid_i = (state_r == S_SEND_TO_ETH);
    payload_to_be_sent_tvalid_i = (state_r == S_SEND_TO_TCP_SENDER);
    uart_out_tvalid_i = (state_r == S_SEND_TO_UART || state_r == S_SEND_HEADER);

    //valid if in polling state
    uart_in_tready_i = (state_r == S_POLL_UART || state_r == S_GET_BYTE || state_r == S_GET_DATA);
    rest_of_frame_tready_i = (state_r == S_POLL_TCP_OUTPUT);
    eth_phy_tready_i = (state_r == S_POLL_FRAMES_OUT);
    app_response_tready_i = (state_r == S_POLL_BRAIN_STATUS);
  end
  
  // tlast signals (not used in this simple mux)
  assign instructions_to_brain_axis_tlast = 1'b0;
  assign eth_payload_axis_tlast = 1'b0;
  assign payload_to_be_sent_axis_tlast = 1'b0;
  assign uart_out_tlast = 1'b0;

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      state_r <= S_POLL_UART;
      state_n <= S_POLL_UART;
      uart_tx_data <= 8'h00;
      uart_rx_data <= 8'h00;
      uart_extra_data <= 8'h00;
      uart_header <= 8'h00;
    end else begin
      case (state_r)
        S_POLL_UART: begin
          if (uart_in_tvalid && uart_in_tready) begin
            case (uart_in_tdata)
              PARROT: begin
                uart_tx_data <= uart_in_tdata;
                uart_header <= PARROT;
                state_r <= S_SEND_HEADER;
              end
              ETH_FRAME_IN: begin
                state_r <= S_GET_BYTE;
                state_n <= S_SEND_TO_ETH;
              end
              INSTRUCTION: begin
                state_r <= S_GET_BYTE;
                state_n <= S_SEND_TO_BRAIN;
              end
              PAYLOAD_COMING: begin
                state_r <= S_GET_BYTE;
                state_n <= S_SEND_TO_TCP_SENDER;
              end
              INFO: begin
                state_r <= S_GET_BYTE;
                state_n <= S_GET_DATA;
              end
              default: begin
                uart_tx_data <= uart_in_tdata;
                uart_header <= PARROT;
                state_r <= S_SEND_HEADER;
              end
            endcase
          end else begin
            state_r <= S_POLL_TCP_OUTPUT;
          end
        end

        S_GET_BYTE: begin
          if (uart_in_tvalid && uart_in_tready) begin
            state_r <= state_n;
            uart_rx_data <= uart_in_tdata;
          end
        end

        S_SEND_TO_ETH: begin
          if (eth_payload_axis_tvalid && eth_payload_axis_tready) begin
            state_r <= S_POLL_UART;
          end
        end
        S_SEND_TO_TCP_SENDER: begin
          if (payload_to_be_sent_axis_tvalid && payload_to_be_sent_axis_tready) begin
            state_r <= S_POLL_UART;
          end
        end
        S_SEND_TO_BRAIN: begin
          if (instructions_to_brain_axis_tvalid && instructions_to_brain_axis_tready) begin
            state_r <= S_POLL_UART;
          end
        end
        S_GET_DATA: begin
          if (uart_in_tvalid && uart_in_tready) begin
            state_r <= S_LOAD_INFO;
            uart_extra_data <= uart_in_tdata;
          end
        end

        S_LOAD_INFO: begin
          case (uart_rx_data)
            // src_mac[47:0]
            0: out_info_src_mac[47:40] <= uart_extra_data;
            1: out_info_src_mac[39:32] <= uart_extra_data;
            2: out_info_src_mac[31:24] <= uart_extra_data;
            3: out_info_src_mac[23:16] <= uart_extra_data;
            4: out_info_src_mac[15:8] <= uart_extra_data;
            5: out_info_src_mac[7:0] <= uart_extra_data;

            // dst_mac[47:0]
            6:  out_info_dst_mac[47:40] <= uart_extra_data;
            7:  out_info_dst_mac[39:32] <= uart_extra_data;
            8:  out_info_dst_mac[31:24] <= uart_extra_data;
            9:  out_info_dst_mac[23:16] <= uart_extra_data;
            10: out_info_dst_mac[15:8] <= uart_extra_data;
            11: out_info_dst_mac[7:0] <= uart_extra_data;

            // src_ip[31:0]
            12: out_info_src_ip[31:24] <= uart_extra_data;
            13: out_info_src_ip[23:16] <= uart_extra_data;
            14: out_info_src_ip[15:8] <= uart_extra_data;
            15: out_info_src_ip[7:0] <= uart_extra_data;

            // dst_ip[31:0]
            16: out_info_dst_ip[31:24] <= uart_extra_data;
            17: out_info_dst_ip[23:16] <= uart_extra_data;
            18: out_info_dst_ip[15:8] <= uart_extra_data;
            19: out_info_dst_ip[7:0] <= uart_extra_data;

            // src_port[15:0]
            20: out_info_src_port[15:8] <= uart_extra_data;
            21: out_info_src_port[7:0] <= uart_extra_data;

            // dst_port[15:0]
            22: out_info_dst_port[15:8] <= uart_extra_data;
            23: out_info_dst_port[7:0] <= uart_extra_data;

            // payload_len[15:0]
            24: out_info_payload_len[15:8] <= uart_extra_data;
            25: out_info_payload_len[7:0] <= uart_extra_data;

            // tcp_checksum[15:0]
            26: out_info_tcp_checksum[15:8] <= uart_extra_data;
            27: out_info_tcp_checksum[7:0] <= uart_extra_data;

            default: ;  // ignore out-of-range
          endcase

          state_r <= S_POLL_UART;
        end

        S_POLL_TCP_OUTPUT: begin
          if (rest_of_frame_axis_tvalid && rest_of_frame_axis_tready) begin
            uart_tx_data <= rest_of_frame_axis_tdata;
            state_r <= S_SEND_HEADER;
            uart_header <= REMAINING_LAYER;
          end else begin
            state_r <= S_POLL_FRAMES_OUT;
          end
        end

        S_POLL_FRAMES_OUT: begin
          if (eth_phy_axis_tvalid && eth_phy_axis_tready) begin
            uart_tx_data <= eth_phy_axis_tdata;
            state_r <= S_SEND_HEADER;
            uart_header <= ETH_FRAME_OUT;
          end else begin
            state_r <= S_POLL_BRAIN_STATUS;
          end
        end
        S_POLL_BRAIN_STATUS: begin
          if (app_response_axis_tvalid && app_response_axis_tready) begin
            uart_tx_data <= app_response_axis_tdata;
            state_r <= S_SEND_HEADER;
            uart_header <= BRAIN_STATUS;
          end else begin
            state_r <= S_POLL_UART;
          end
        end

        S_SEND_HEADER: begin
          if (uart_out_tvalid && uart_out_tready) begin
            state_r <= S_SEND_TO_UART;
          end
        end


        S_SEND_TO_UART: begin
          if (uart_out_tvalid && uart_out_tready) begin
            state_r <= S_POLL_UART;
          end
        end

        default: begin
          state_r <= S_POLL_UART;
        end

      endcase

    end
  end

endmodule
