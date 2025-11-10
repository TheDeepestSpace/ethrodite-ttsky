if {[file exists work]} {
    vdel -all
}
vlib work

# Compile sources
vlog -sv axi_stream_if.sv
vlog -sv tcp_top.sv
vlog -sv tcp_full_tb.sv

# Simulate in console mode
vsim -c work.tcp_full_tb
run -all
quit -f
