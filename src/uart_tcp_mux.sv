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
    
    // Connection info (latched on instruction)
    output tcp_command_info     out_info,

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

  // No internal interfaces needed - using flattened ports directly

  // Packet type constants
  localparam logic [7:0] PARROT = 8'd0;  // send back what we sent them
  localparam logic [7:0] ETH_FRAME_IN = 8'd1;
  localparam logic [7:0] ETH_FRAME_OUT = 8'd2;
  localparam logic [7:0] REMAINING_LAYER = 8'd3;
  localparam logic [7:0] INSTRUCTION = 8'd4;
  localparam logic [7:0] BRAIN_STATUS = 8'd5;
  localparam logic [7:0] PAYLOAD_COMING = 8'd6;
  localparam logic [7:0] INFO = 8'd7;

  // UART byte interface
  logic [7:0] uart_rx_data, uart_tx_data, uart_extra_data, uart_header;
  logic uart_rx_valid, uart_tx_valid;
  logic uart_rx_ready, uart_tx_ready;

  typedef enum logic [3:0] {
    S_POLL_UART,
    S_SEND_TO_BRAIN,
    S_SEND_TO_ETH,
    S_SEND_TO_TCP_SENDER,
    S_LOAD_INFO,

    S_SEND_TO_UART,
    S_POLL_TCP_OUTPUT,   //layers under tcp
    S_POLL_FRAMES_OUT,
    S_POLL_BRAIN_STATUS, // full frames being sent to server

    S_GET_DATA,    // because for out_info, we first get address, then get the actual data to load
    S_GET_BYTE,    // general purpose state to load state into reg
    S_SEND_HEADER
  } state_e;
  state_e state_r, state_n;

  always_comb begin
    //all same data for UART --> REST OF CHIP
    instructions_to_brain_axis_tdata = uart_rx_data;
    eth_payload_axis_tdata = uart_rx_data;
    payload_to_be_sent_axis_tdata = uart_rx_data;
    uart_out_tdata = (state_r == S_SEND_HEADER) ? uart_header : uart_tx_data;

    //valid if in outputting state
    instructions_to_brain_axis_tvalid = (state_r == S_SEND_TO_BRAIN);
    eth_payload_axis_tvalid = (state_r == S_SEND_TO_ETH);
    payload_to_be_sent_axis_tvalid = (state_r == S_SEND_TO_TCP_SENDER);
    uart_out_tvalid = (state_r == S_SEND_TO_UART || state_r == S_SEND_HEADER);

    //valid if in polling state
    uart_in_tready = (state_r == S_POLL_UART || state_r == S_GET_BYTE || state_r == S_GET_DATA);
    rest_of_frame_axis_tready = (state_r == S_POLL_TCP_OUTPUT);
    eth_phy_axis_tready = (state_r == S_POLL_FRAMES_OUT);
    app_response_axis_tready = (state_r == S_POLL_BRAIN_STATUS);
    
    // tlast signals (not used in this simple mux)
    instructions_to_brain_axis_tlast = 1'b0;
    eth_payload_axis_tlast = 1'b0;
    payload_to_be_sent_axis_tlast = 1'b0;
    uart_out_tlast = 1'b0;
  end

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      state_r <= S_POLL_UART;
    end else begin
      case (state_r)
        S_POLL_UART: begin
          if (uart_in_tvalid && uart_in_tready) begin
            case (uart_in_tdata)
              PARROT: begin
                $display("got parrot");
                uart_tx_data <= uart_in_tdata;
                uart_header <= PARROT;
                state_r <= S_SEND_HEADER;
              end
              ETH_FRAME_IN: begin
                $display("got eth frame");
                state_r <= S_GET_BYTE;
                state_n <= S_SEND_TO_ETH;
              end
              INSTRUCTION: begin
                $display("got instruction");
                state_r <= S_GET_BYTE;
                state_n <= S_SEND_TO_BRAIN;
              end
              PAYLOAD_COMING: begin
                $display("got payload");
                state_r <= S_GET_BYTE;
                state_n <= S_SEND_TO_TCP_SENDER;
              end
              INFO: begin
                $display("got info");
                state_r <= S_GET_BYTE;
                state_n <= S_GET_DATA;
              end
              default: begin
                $display("got garbage: %h", uart_in_tdata);
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
            0: out_info.src_mac[47:40] <= uart_extra_data;
            1: out_info.src_mac[39:32] <= uart_extra_data;
            2: out_info.src_mac[31:24] <= uart_extra_data;
            3: out_info.src_mac[23:16] <= uart_extra_data;
            4: out_info.src_mac[15:8] <= uart_extra_data;
            5: out_info.src_mac[7:0] <= uart_extra_data;

            // dst_mac[47:0]
            6:  out_info.dst_mac[47:40] <= uart_extra_data;
            7:  out_info.dst_mac[39:32] <= uart_extra_data;
            8:  out_info.dst_mac[31:24] <= uart_extra_data;
            9:  out_info.dst_mac[23:16] <= uart_extra_data;
            10: out_info.dst_mac[15:8] <= uart_extra_data;
            11: out_info.dst_mac[7:0] <= uart_extra_data;

            // src_ip[31:0]
            12: out_info.src_ip[31:24] <= uart_extra_data;
            13: out_info.src_ip[23:16] <= uart_extra_data;
            14: out_info.src_ip[15:8] <= uart_extra_data;
            15: out_info.src_ip[7:0] <= uart_extra_data;

            // dst_ip[31:0]
            16: out_info.dst_ip[31:24] <= uart_extra_data;
            17: out_info.dst_ip[23:16] <= uart_extra_data;
            18: out_info.dst_ip[15:8] <= uart_extra_data;
            19: out_info.dst_ip[7:0] <= uart_extra_data;

            // src_port[15:0]
            20: out_info.src_port[15:8] <= uart_extra_data;
            21: out_info.src_port[7:0] <= uart_extra_data;

            // dst_port[15:0]
            22: out_info.dst_port[15:8] <= uart_extra_data;
            23: out_info.dst_port[7:0] <= uart_extra_data;

            // payload_len[15:0]
            24: out_info.payload_len[15:8] <= uart_extra_data;
            25: out_info.payload_len[7:0] <= uart_extra_data;

            // tcp_checksum[15:0]
            26: out_info.tcp_checksum[15:8] <= uart_extra_data;
            27: out_info.tcp_checksum[7:0] <= uart_extra_data;

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
