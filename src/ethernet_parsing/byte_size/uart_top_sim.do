# UART TCP Top Testbench Simulation Script
# Run this with: vsim -c -do uart_top_sim.do

# Create work library if it doesn't exist
vlib work

# Compile all required SystemVerilog files
echo "Compiling SystemVerilog files..."

# Basic interfaces and packages
vlog +incdir+. axi_stream_if.sv
vlog +incdir+. ethernet_info.svh

# UART modules
vlog +incdir+. uart_core.sv
vlog +incdir+. uart_tcp_mux.sv

# TCP stack modules (compile in dependency order)
vlog +incdir+. crc32.sv
vlog +incdir+. ethernet_ipv4_handler.sv
vlog +incdir+. tcp_handler.sv
vlog +incdir+. tcp_reorder_buffer.sv
vlog +incdir+. tcp_sender.sv
vlog +incdir+. tcp_brain.sv
vlog +incdir+. tcp_top.sv

# Top-level wrapper and testbench
vlog +incdir+. uart_top.sv
vlog +incdir+. uart_top_tb.sv

echo "Starting simulation..."

# Start simulation
vsim -t 1ns uart_top_tb

# Add waves for debugging
add wave -group "Top Level" /uart_top_tb/clk
add wave -group "Top Level" /uart_top_tb/rst_n
add wave -group "Top Level" /uart_top_tb/uart_rx
add wave -group "Top Level" /uart_top_tb/uart_tx
add wave -group "Top Level" /uart_top_tb/debug_status
add wave -group "Top Level" /uart_top_tb/connection_active

# UART Core signals
add wave -group "UART Core" /uart_top_tb/dut/u_uart_mux/u_uart/uart_rx
add wave -group "UART Core" /uart_top_tb/dut/u_uart_mux/u_uart/uart_tx
add wave -group "UART Core" /uart_top_tb/dut/u_uart_mux/u_uart/rx_data
add wave -group "UART Core" /uart_top_tb/dut/u_uart_mux/u_uart/rx_valid
add wave -group "UART Core" /uart_top_tb/dut/u_uart_mux/u_uart/tx_data
add wave -group "UART Core" /uart_top_tb/dut/u_uart_mux/u_uart/tx_valid
add wave -group "UART Core" /uart_top_tb/dut/u_uart_mux/u_uart/tx_ready

# UART MUX signals
add wave -group "UART MUX" /uart_top_tb/dut/u_uart_mux/rx_state
add wave -group "UART MUX" /uart_top_tb/dut/u_uart_mux/tx_state
add wave -group "UART MUX" /uart_top_tb/dut/u_uart_mux/rx_packet_type
add wave -group "UART MUX" /uart_top_tb/dut/u_uart_mux/rx_length
add wave -group "UART MUX" /uart_top_tb/dut/u_uart_mux/rx_axi_sending_app
add wave -group "UART MUX" /uart_top_tb/dut/u_uart_mux/rx_axi_sending_eth

# AXI Stream interfaces
add wave -group "AXI Instruction" /uart_top_tb/dut/instruction_if/tvalid
add wave -group "AXI Instruction" /uart_top_tb/dut/instruction_if/tready
add wave -group "AXI Instruction" /uart_top_tb/dut/instruction_if/tdata
add wave -group "AXI Instruction" /uart_top_tb/dut/instruction_if/tlast

add wave -group "AXI Payload" /uart_top_tb/dut/payload_if/tvalid
add wave -group "AXI Payload" /uart_top_tb/dut/payload_if/tready
add wave -group "AXI Payload" /uart_top_tb/dut/payload_if/tdata
add wave -group "AXI Payload" /uart_top_tb/dut/payload_if/tlast

add wave -group "AXI Response" /uart_top_tb/dut/response_if/tvalid
add wave -group "AXI Response" /uart_top_tb/dut/response_if/tready
add wave -group "AXI Response" /uart_top_tb/dut/response_if/tdata
add wave -group "AXI Response" /uart_top_tb/dut/response_if/tlast

add wave -group "AXI PHY" /uart_top_tb/dut/phy_if/tvalid
add wave -group "AXI PHY" /uart_top_tb/dut/phy_if/tready
add wave -group "AXI PHY" /uart_top_tb/dut/phy_if/tdata
add wave -group "AXI PHY" /uart_top_tb/dut/phy_if/tlast

# Testbench signals
add wave -group "Testbench" /uart_top_tb/tick_count
add wave -group "Testbench" /uart_top_tb/last_activity
add wave -group "Testbench" /uart_top_tb/tx_frame_buffer
add wave -group "Testbench" /uart_top_tb/uart_tx_valid
add wave -group "Testbench" /uart_top_tb/uart_tx_byte

# Configure wave window
configure wave -namecolwidth 200
configure wave -valuecolwidth 100
configure wave -justifyvalue left
configure wave -signalnamewidth 1

# Run simulation
echo "Running simulation for 50ms..."
run 50ms

echo "Simulation completed. Use 'wave zoom full' to see all activity."
wave zoom full
