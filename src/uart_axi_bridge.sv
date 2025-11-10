// uart_axi_bridge.sv
`include "axi_stream_if.sv"
// `include "UART_wrapper.sv"

module uart_axi_bridge #(
    parameter int DATA_WIDTH = 8,
    parameter int CLK_BITS   = 8
)(
    input  logic clk,
    input  logic rst_n,

    // AXI-stream side (connected to mux)
    axi_stream_if.slave  uart_in,   // incoming bytes from MUX (TX data to send)
    axi_stream_if.master uart_out,  // outgoing bytes to MUX (RX data received)

    // Physical UART
    output logic uart_tx,           // serial TX pin
    input  logic uart_rx,           // serial RX pin

    // Baud rate divider
    input  logic [CLK_BITS-1:0] clk_per_bit
);

    // ======================================
    // UART wrapper instance
    // ======================================
    logic [DATA_WIDTH-1:0] tx_data;
    logic tx_en;
    logic tx_done;
    logic tx_busy;

    logic [DATA_WIDTH-1:0] rx_data;
    logic rx_done;
    logic rx_parity_err;

    UART_wrapper #(
        .CLK_BITS(CLK_BITS),
        .DATA_WIDTH(DATA_WIDTH),
        .PARITY_BITS(0),
        .STOP_BITS(1)
    ) uart_core (
        .clk(clk),
        .rst(~rst_n),

        .clk_per_bit(clk_per_bit),

        .TX_dataIn(tx_data),
        .TX_en(tx_en),

        .RX_dataIn(uart_rx),

        .TX_out(uart_tx),
        .TX_done(tx_done),
        .TX_busy(tx_busy),

        .RX_dataOut(rx_data),
        .RX_done(rx_done),
        .RX_parityError(rx_parity_err)
    );

    // ======================================
    // AXI to UART TX adapter
    // ======================================
    assign uart_in.tready = !tx_busy;   // UART can accept a byte if not busy
    assign tx_en = uart_in.tvalid && uart_in.tready;
    assign tx_data = uart_in.tdata;

    // ======================================
    // UART RX to AXI adapter
    // ======================================
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            uart_out.tvalid <= 1'b0;
            uart_out.tdata  <= '0;
        end else begin
            // When UART RX finishes receiving a byte
            if (rx_done) begin
                uart_out.tdata  <= rx_data;
                $display("sending %h", rx_data);
                uart_out.tvalid <= 1'b1;
            end
            // Clear valid when mux accepts it
            else if (uart_out.tvalid && uart_out.tready) begin
                uart_out.tvalid <= 1'b0;
            end
        end
    end

endmodule
