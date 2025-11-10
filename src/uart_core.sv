module uart_core #(
    parameter BAUD_RATE = 115200,
    parameter CLK_FREQ  = 50000000
)(
    input  logic       clk,
    input  logic       rst_n,

    // Physical UART interface
    input  logic       uart_rx,
    output logic       uart_tx,

    // Internal byte interface
    output logic [7:0] rx_data,
    output logic       rx_valid,
    input  logic       rx_ready,

    input  logic [7:0] tx_data,
    input  logic       tx_valid,
    output logic       tx_ready
);

    localparam int BAUD_DIV = CLK_FREQ / BAUD_RATE;

    // UART RX logic
    logic [15:0] rx_clk_div;
    logic [3:0]  rx_bit_cnt;
    logic [7:0]  rx_shift_reg;
    logic        rx_active;

    // UART TX logic
    logic [15:0] tx_clk_div;
    logic [3:0]  tx_bit_cnt;
    logic [9:0]  tx_shift_reg; // start + 8 data + stop
    logic        tx_active;

    // RX implementation
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rx_clk_div <= 0;
            rx_bit_cnt <= 0;
            rx_shift_reg <= 0;
            rx_active <= 0;
            rx_valid <= 0;
        end else begin
            rx_valid <= 0;

            if (!rx_active && !uart_rx) begin
                // Start bit detected
                rx_active <= 1;
                rx_clk_div <= BAUD_DIV/2;
                rx_bit_cnt <= 0;
            end else if (rx_active) begin
                if (rx_clk_div == 0) begin
                    rx_clk_div <= BAUD_DIV - 1;
                    if (rx_bit_cnt == 8) begin
                        // Stop bit
                        rx_active <= 0;
                        rx_valid <= 1;
                        rx_data <= rx_shift_reg;
                    end else begin
                        rx_shift_reg <= {uart_rx, rx_shift_reg[7:1]};
                        rx_bit_cnt <= rx_bit_cnt + 1;
                    end
                end else begin
                    rx_clk_div <= rx_clk_div - 1;
                end
            end
        end
    end

    // TX implementation
    assign tx_ready = !tx_active;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_clk_div <= 0;
            tx_bit_cnt <= 0;
            tx_shift_reg <= 10'h3FF;
            tx_active <= 0;
            uart_tx <= 1;
        end else begin
            if (!tx_active && tx_valid && tx_ready) begin
                tx_active <= 1;
                tx_shift_reg <= {1'b1, tx_data, 1'b0}; // stop + data + start
                tx_clk_div <= BAUD_DIV - 1;
                tx_bit_cnt <= 0;
            end else if (tx_active) begin
                if (tx_clk_div == 0) begin
                    tx_clk_div <= BAUD_DIV - 1;
                    uart_tx <= tx_shift_reg[0];
                    tx_shift_reg <= {1'b1, tx_shift_reg[9:1]};
                    if (tx_bit_cnt == 9) begin
                        tx_active <= 0;
                    end else begin
                        tx_bit_cnt <= tx_bit_cnt + 1;
                    end
                end else begin
                    tx_clk_div <= tx_clk_div - 1;
                end
            end
        end
    end

endmodule
