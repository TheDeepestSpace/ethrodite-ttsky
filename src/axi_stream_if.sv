// ============================================================
// AXI4-Stream Interface
// Fully parameterized for any data width
// Author: rob
// ============================================================

`ifndef AXI_STREAM_IF_SV
`define AXI_STREAM_IF_SV

interface axi_stream_if #(
    parameter int DATA_WIDTH = 8   // default data width
);

    // Derived parameters

    // -----------------------------
    // AXI4-Stream signals
    // -----------------------------
    logic [DATA_WIDTH-1:0] tdata;
    logic                  tvalid;
    logic                  tready;
    logic                  tlast;

    // -----------------------------
    // Optional: typedef for struct
    // -----------------------------
    typedef struct packed {
        logic [DATA_WIDTH-1:0] tdata;
        logic                  tvalid;
        logic                  tready;
        logic                  tlast;
    } axis_word_t;

    // -----------------------------
    // Modports
    // -----------------------------
    modport master (
        output tdata, tvalid, tlast,
        input  tready
    );

    modport slave (
        input  tdata, tvalid, tlast,
        output tready
    );

endinterface : axi_stream_if

`endif // AXI_STREAM_IF_SV