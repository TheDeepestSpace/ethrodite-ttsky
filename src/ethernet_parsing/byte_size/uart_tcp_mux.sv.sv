// uart_tcp_mux.sv
module uart_tcp_mux #(
    parameter int DATA_WIDTH = 64
)(
    input  logic clk,
    input  logic rst_n,

    // Physical UART
    input  logic uart_rx,
    output logic uart_tx,

    // Application instruction interfaces (connect to tcp_top)
    axi_stream_if.master app_instruction_axis,
    axi_stream_if.slave  app_response_axis,

    // Ethernet PHY interfaces (connect to tcp_top)
    axi_stream_if.master eth_payload_axis,
    axi_stream_if.slave  eth_phy_axis
);

    localparam int BYTES = DATA_WIDTH / 8;

    // Packet type constants
    localparam logic [7:0] UART_START_BYTE = 8'h5A;
    localparam logic [7:0] PKT_TYPE_APP_CMD = 8'h01;
    localparam logic [7:0] PKT_TYPE_APP_RESP = 8'h02;
    localparam logic [7:0] PKT_TYPE_ETH_RX = 8'h10;
    localparam logic [7:0] PKT_TYPE_ETH_TX = 8'h11;

    // UART byte interface
    logic [7:0] uart_rx_data, uart_tx_data;
    logic uart_rx_valid, uart_tx_valid;
    logic uart_rx_ready, uart_tx_ready;

    // Internal packet buffers (reduced size for minimal buffering)
    logic [7:0] rx_buffer [0:63];  // Small buffer for non-streaming packets
    logic [15:0] rx_length, rx_count;
    logic [7:0] rx_packet_type;

    // Streaming conversion signals
    logic [15:0] rx_axi_byte_idx, tx_axi_byte_idx;
    logic [15:0] rx_axi_packet_len, tx_axi_packet_len;
    logic rx_axi_sending_app, rx_axi_sending_eth;
    logic tx_axi_receiving_app, tx_axi_receiving_eth;
    logic [DATA_WIDTH-1:0] rx_axi_beat_buffer, tx_axi_beat_buffer;
    logic [BYTES-1:0] rx_axi_beat_strb, tx_axi_beat_strb;
    logic [3:0] rx_bytes_in_beat, tx_bytes_in_beat;

    // RX State Machine
    typedef enum logic [3:0] {
        RX_IDLE,
        RX_TYPE,
        RX_LEN_H,
        RX_LEN_L,
        RX_DATA,
        RX_DATA_STREAM,  // New: streaming data to AXI
        RX_CRC,
        RX_DISPATCH
    } rx_state_e;

    rx_state_e rx_state;

    // TX State Machine
    typedef enum logic [3:0] {
        TX_IDLE,
        TX_START,
        TX_TYPE,
        TX_LEN_H,
        TX_LEN_L,
        TX_DATA,
        TX_DATA_STREAM,  // New: streaming data from AXI
        TX_CRC,
        TX_COMPLETE
    } tx_state_e;

    tx_state_e tx_state;
    logic [15:0] tx_length, tx_count;
    logic [7:0] tx_packet_type;

    // UART Core instance
    uart_core u_uart (
        .clk(clk),
        .rst_n(rst_n),
        .uart_rx(uart_rx),
        .uart_tx(uart_tx),
        .rx_data(uart_rx_data),
        .rx_valid(uart_rx_valid),
        .rx_ready(uart_rx_ready),
        .tx_data(uart_tx_data),
        .tx_valid(uart_tx_valid),
        .tx_ready(uart_tx_ready)
    );

    // RX Packet Processing
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rx_state <= RX_IDLE;
            app_instruction_axis.tvalid <= 0;
            eth_payload_axis.tvalid <= 0;
            rx_axi_byte_idx <= 0;
            rx_bytes_in_beat <= 0;
            rx_axi_sending_app <= 0;
            rx_axi_sending_eth <= 0;
        end else begin
            case (rx_state)
                RX_IDLE: begin
                    if (uart_rx_valid && uart_rx_data == UART_START_BYTE) begin
                        rx_state <= RX_TYPE;
                        rx_axi_byte_idx <= 0;
                        rx_bytes_in_beat <= 0;
                    end
                end

                RX_TYPE: begin
                    if (uart_rx_valid) begin
                        rx_packet_type <= uart_rx_data;
                        rx_state <= RX_LEN_H;
                    end
                end

                RX_LEN_H: begin
                    if (uart_rx_valid) begin
                        rx_length[15:8] <= uart_rx_data;
                        rx_state <= RX_LEN_L;
                    end
                end

                RX_LEN_L: begin
                    if (uart_rx_valid) begin
                        rx_length[7:0] <= uart_rx_data;
                        rx_count <= 0;
                        rx_axi_packet_len <= {rx_length[15:8], uart_rx_data};

                        // Always use streaming for better memory efficiency
                        case (rx_packet_type)
                            PKT_TYPE_APP_CMD: begin
                                rx_axi_sending_app <= 1;
                                rx_state <= RX_DATA_STREAM;
                            end
                            PKT_TYPE_ETH_RX: begin
                                rx_axi_sending_eth <= 1;
                                rx_state <= RX_DATA_STREAM;
                            end
                            default: begin
                                rx_state <= RX_CRC; // Skip data for unknown types
                            end
                        endcase
                    end
                end

                RX_DATA: begin
                    if (uart_rx_valid) begin
                        rx_buffer[rx_count] <= uart_rx_data;
                        rx_count <= rx_count + 1;
                        if (rx_count == rx_length - 1) begin
                            rx_state <= RX_CRC;
                            rx_count <= 0;
                        end
                    end
                end

                RX_DATA_STREAM: begin
                    if (uart_rx_valid && uart_rx_ready) begin
                        // Pack byte into current beat
                        rx_axi_beat_buffer[rx_bytes_in_beat*8 +: 8] <= uart_rx_data;
                        rx_axi_beat_strb[rx_bytes_in_beat] <= 1'b1;
                        rx_bytes_in_beat <= rx_bytes_in_beat + 1;
                        rx_count <= rx_count + 1;

                        // Send beat when full or last byte
                        if (rx_bytes_in_beat == BYTES-1 || rx_count == rx_length-1) begin
                            rx_send_axi_beat();
                        end

                        // Check if packet complete
                        if (rx_count == rx_length - 1) begin
                            rx_state <= RX_CRC;
                            rx_count <= 0;
                        end
                    end
                end

                RX_CRC: begin
                    if (uart_rx_valid) begin
                        rx_count <= rx_count + 1;
                        if (rx_count == 1) begin // 2-byte CRC
                            rx_state <= RX_DISPATCH;
                        end
                    end
                end

                RX_DISPATCH: begin
                    // Only for non-streaming packets (fallback)
                    if (!rx_axi_sending_app && !rx_axi_sending_eth) begin
                        case (rx_packet_type)
                            PKT_TYPE_APP_CMD: begin
                                convert_to_axi_stream(rx_buffer, rx_length, 1'b1); // is_app = true
                            end
                            PKT_TYPE_ETH_RX: begin
                                convert_to_axi_stream(rx_buffer, rx_length, 1'b0); // is_app = false
                            end
                        endcase
                    end
                    rx_state <= RX_IDLE;
                end
            endcase
        end
    end

    // TX Arbitration and Processing with streaming
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_state <= TX_IDLE;
            app_response_axis.tready <= 0;
            eth_phy_axis.tready <= 0;
            tx_axi_receiving_app <= 0;
            tx_axi_receiving_eth <= 0;
            tx_axi_byte_idx <= 0;
            tx_bytes_in_beat <= 0;
        end else begin
            case (tx_state)
                TX_IDLE: begin
                    // Check for AXI data to transmit
                    if (app_response_axis.tvalid && !tx_axi_receiving_app && !tx_axi_receiving_eth) begin
                        tx_packet_type <= PKT_TYPE_APP_RESP;
                        tx_axi_receiving_app <= 1;
                        app_response_axis.tready <= 1;
                        tx_state <= TX_START;
                        // Calculate length from first beat
                        tx_calculate_length(1'b1); // is_app = true
                    end else if (eth_phy_axis.tvalid && !tx_axi_receiving_app && !tx_axi_receiving_eth) begin
                        tx_packet_type <= PKT_TYPE_ETH_TX;
                        tx_axi_receiving_eth <= 1;
                        eth_phy_axis.tready <= 1;
                        tx_state <= TX_START;
                        tx_calculate_length(1'b0); // is_app = false
                    end
                end

                TX_START: begin
                    if (uart_tx_ready) begin
                        uart_tx_data <= UART_START_BYTE;
                        uart_tx_valid <= 1;
                        tx_state <= TX_TYPE;
                    end
                end

                TX_TYPE: begin
                    if (uart_tx_ready) begin
                        uart_tx_data <= tx_packet_type;
                        uart_tx_valid <= 1;
                        tx_state <= TX_LEN_H;
                    end
                end

                TX_LEN_H: begin
                    if (uart_tx_ready) begin
                        uart_tx_data <= tx_axi_packet_len[15:8];
                        uart_tx_valid <= 1;
                        tx_state <= TX_LEN_L;
                    end
                end

                TX_LEN_L: begin
                    if (uart_tx_ready) begin
                        uart_tx_data <= tx_axi_packet_len[7:0];
                        uart_tx_valid <= 1;
                        tx_state <= TX_DATA_STREAM;
                        tx_axi_byte_idx <= 0;
                        tx_bytes_in_beat <= 0;
                    end
                end

                TX_DATA_STREAM: begin
                    // Stream AXI data to UART
                    if (tx_axi_receiving_app && app_response_axis.tvalid) begin
                        tx_stream_axi_to_uart(1'b1); // is_app = true
                    end else if (tx_axi_receiving_eth && eth_phy_axis.tvalid) begin
                        tx_stream_axi_to_uart(1'b0); // is_app = false
                    end

                    if (tx_axi_byte_idx >= tx_axi_packet_len) begin
                        tx_state <= TX_CRC;
                        tx_count <= 0;
                    end
                end

                TX_CRC: begin
                    if (uart_tx_ready) begin
                        tx_count <= tx_count + 1;
                        // Send 2-byte CRC
                        uart_tx_data <= (tx_count == 0) ? 8'h00 : 8'h00; // Placeholder CRC
                        uart_tx_valid <= 1;

                        if (tx_count == 1) begin
                            tx_state <= TX_COMPLETE;
                        end
                    end
                end

                TX_COMPLETE: begin
                    // Clean up
                    tx_axi_receiving_app <= 0;
                    tx_axi_receiving_eth <= 0;
                    app_response_axis.tready <= 0;
                    eth_phy_axis.tready <= 0;
                    tx_state <= TX_IDLE;
                end
            endcase
        end
    end

    // Task to send RX AXI beat
    task rx_send_axi_beat();
        if (rx_axi_sending_app) begin
            app_instruction_axis.tdata <= rx_axi_beat_buffer;
            app_instruction_axis.tkeep <= rx_axi_beat_strb;
            app_instruction_axis.tvalid <= 1;
            app_instruction_axis.tlast <= (rx_count >= rx_length - 1);

            if (app_instruction_axis.tready || !app_instruction_axis.tvalid) begin
                rx_clear_beat_buffer();
                if (app_instruction_axis.tlast) begin
                    rx_axi_sending_app <= 0;
                end
            end
        end else if (rx_axi_sending_eth) begin
            eth_payload_axis.tdata <= rx_axi_beat_buffer;
            eth_payload_axis.tkeep <= rx_axi_beat_strb;
            eth_payload_axis.tvalid <= 1;
            eth_payload_axis.tlast <= (rx_count >= rx_length - 1);

            if (eth_payload_axis.tready || !eth_payload_axis.tvalid) begin
                rx_clear_beat_buffer();
                if (eth_payload_axis.tlast) begin
                    rx_axi_sending_eth <= 0;
                end
            end
        end
    endtask

    // Task to clear RX beat buffer
    task rx_clear_beat_buffer();
        rx_axi_beat_buffer <= 0;
        rx_axi_beat_strb <= 0;
        rx_bytes_in_beat <= 0;
    endtask

    // Task to calculate TX packet length from AXI stream
    task tx_calculate_length(input logic is_app);
        // For now, estimate length - in practice you might need to buffer first beat
        // This is a simplified implementation
        tx_axi_packet_len <= 64; // Placeholder - needs proper implementation based on your protocol
    endtask

    // Task to stream AXI data to UART
    task tx_stream_axi_to_uart(input logic is_app);
        if (uart_tx_ready) begin
            if (is_app) begin
                // Extract byte from app response AXI beat
                uart_tx_data <= app_response_axis.tdata[tx_bytes_in_beat*8 +: 8];
                uart_tx_valid <= app_response_axis.tkeep[tx_bytes_in_beat];
            end else begin
                // Extract byte from ethernet PHY AXI beat
                uart_tx_data <= eth_phy_axis.tdata[tx_bytes_in_beat*8 +: 8];
                uart_tx_valid <= eth_phy_axis.tkeep[tx_bytes_in_beat];
            end

            tx_bytes_in_beat <= tx_bytes_in_beat + 1;
            tx_axi_byte_idx <= tx_axi_byte_idx + 1;

            // Move to next AXI beat when current one is exhausted
            if (tx_bytes_in_beat == BYTES-1 ||
                (is_app ? !app_response_axis.tkeep[tx_bytes_in_beat+1] : !eth_phy_axis.tkeep[tx_bytes_in_beat+1])) begin

                if (is_app) begin
                    app_response_axis.tready <= 1; // Accept next beat
                end else begin
                    eth_phy_axis.tready <= 1; // Accept next beat
                end
                tx_bytes_in_beat <= 0;

                // Check for end of stream
                if ((is_app && app_response_axis.tlast) || (!is_app && eth_phy_axis.tlast)) begin
                    // End of AXI stream
                    tx_axi_receiving_app <= 0;
                    tx_axi_receiving_eth <= 0;
                end
            end
        end
    endtask

    // Helper task to convert buffer to AXI Stream (fallback for non-streaming)
    task convert_to_axi_stream(
        input logic [7:0] buffer[],
        input logic [15:0] length,
        input logic is_app
    );
        // Simplified implementation for fallback cases
        // In practice, this would need proper beat packing similar to streaming version
        // This is a placeholder - most packets should use streaming mode
    endtask

    // Handle backpressure for RX direction
    always_comb begin
        if (rx_state == RX_DATA_STREAM) begin
            if (rx_axi_sending_app) begin
                uart_rx_ready = app_instruction_axis.tready || !app_instruction_axis.tvalid;
            end else if (rx_axi_sending_eth) begin
                uart_rx_ready = eth_payload_axis.tready || !eth_payload_axis.tvalid;
            end else begin
                uart_rx_ready = 1;
            end
        end else begin
            uart_rx_ready = 1;
        end
    end

endmodule
