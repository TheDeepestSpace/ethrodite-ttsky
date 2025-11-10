// vim: ts=4 sw=4 expandtab

`ifndef CRC32_SV
`define CRC32_SV
// THIS IS GENERATED VERILOG CODE.
// https://bues.ch/h/crcgen
// 
// This code is Public Domain.
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
// RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
// NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
// USE OR PERFORMANCE OF THIS SOFTWARE.

// CRC polynomial coefficients: x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
//                              0xEDB88320 (hex)
// CRC width:                   32 bits
// CRC shift direction:         right (little endian)
// Input word width:            8 bits

function automatic [31:0] crc;
    input [31:0] crcIn;
    input [7:0] data;
begin
    crc[0] = crcIn[2] ^ crcIn[8] ^ data[2];
    crc[1] = crcIn[0] ^ crcIn[3] ^ crcIn[9] ^ data[0] ^ data[3];
    crc[2] = crcIn[0] ^ crcIn[1] ^ crcIn[4] ^ crcIn[10] ^ data[0] ^ data[1] ^ data[4];
    crc[3] = crcIn[1] ^ crcIn[2] ^ crcIn[5] ^ crcIn[11] ^ data[1] ^ data[2] ^ data[5];
    crc[4] = crcIn[0] ^ crcIn[2] ^ crcIn[3] ^ crcIn[6] ^ crcIn[12] ^ data[0] ^ data[2] ^ data[3] ^ data[6];
    crc[5] = crcIn[1] ^ crcIn[3] ^ crcIn[4] ^ crcIn[7] ^ crcIn[13] ^ data[1] ^ data[3] ^ data[4] ^ data[7];
    crc[6] = crcIn[4] ^ crcIn[5] ^ crcIn[14] ^ data[4] ^ data[5];
    crc[7] = crcIn[0] ^ crcIn[5] ^ crcIn[6] ^ crcIn[15] ^ data[0] ^ data[5] ^ data[6];
    crc[8] = crcIn[1] ^ crcIn[6] ^ crcIn[7] ^ crcIn[16] ^ data[1] ^ data[6] ^ data[7];
    crc[9] = crcIn[7] ^ crcIn[17] ^ data[7];
    crc[10] = crcIn[2] ^ crcIn[18] ^ data[2];
    crc[11] = crcIn[3] ^ crcIn[19] ^ data[3];
    crc[12] = crcIn[0] ^ crcIn[4] ^ crcIn[20] ^ data[0] ^ data[4];
    crc[13] = crcIn[0] ^ crcIn[1] ^ crcIn[5] ^ crcIn[21] ^ data[0] ^ data[1] ^ data[5];
    crc[14] = crcIn[1] ^ crcIn[2] ^ crcIn[6] ^ crcIn[22] ^ data[1] ^ data[2] ^ data[6];
    crc[15] = crcIn[2] ^ crcIn[3] ^ crcIn[7] ^ crcIn[23] ^ data[2] ^ data[3] ^ data[7];
    crc[16] = crcIn[0] ^ crcIn[2] ^ crcIn[3] ^ crcIn[4] ^ crcIn[24] ^ data[0] ^ data[2] ^ data[3] ^ data[4];
    crc[17] = crcIn[0] ^ crcIn[1] ^ crcIn[3] ^ crcIn[4] ^ crcIn[5] ^ crcIn[25] ^ data[0] ^ data[1] ^ data[3] ^ data[4] ^ data[5];
    crc[18] = crcIn[0] ^ crcIn[1] ^ crcIn[2] ^ crcIn[4] ^ crcIn[5] ^ crcIn[6] ^ crcIn[26] ^ data[0] ^ data[1] ^ data[2] ^ data[4] ^ data[5] ^ data[6];
    crc[19] = crcIn[1] ^ crcIn[2] ^ crcIn[3] ^ crcIn[5] ^ crcIn[6] ^ crcIn[7] ^ crcIn[27] ^ data[1] ^ data[2] ^ data[3] ^ data[5] ^ data[6] ^ data[7];
    crc[20] = crcIn[3] ^ crcIn[4] ^ crcIn[6] ^ crcIn[7] ^ crcIn[28] ^ data[3] ^ data[4] ^ data[6] ^ data[7];
    crc[21] = crcIn[2] ^ crcIn[4] ^ crcIn[5] ^ crcIn[7] ^ crcIn[29] ^ data[2] ^ data[4] ^ data[5] ^ data[7];
    crc[22] = crcIn[2] ^ crcIn[3] ^ crcIn[5] ^ crcIn[6] ^ crcIn[30] ^ data[2] ^ data[3] ^ data[5] ^ data[6];
    crc[23] = crcIn[3] ^ crcIn[4] ^ crcIn[6] ^ crcIn[7] ^ crcIn[31] ^ data[3] ^ data[4] ^ data[6] ^ data[7];
    crc[24] = crcIn[0] ^ crcIn[2] ^ crcIn[4] ^ crcIn[5] ^ crcIn[7] ^ data[0] ^ data[2] ^ data[4] ^ data[5] ^ data[7];
    crc[25] = crcIn[0] ^ crcIn[1] ^ crcIn[2] ^ crcIn[3] ^ crcIn[5] ^ crcIn[6] ^ data[0] ^ data[1] ^ data[2] ^ data[3] ^ data[5] ^ data[6];
    crc[26] = crcIn[0] ^ crcIn[1] ^ crcIn[2] ^ crcIn[3] ^ crcIn[4] ^ crcIn[6] ^ crcIn[7] ^ data[0] ^ data[1] ^ data[2] ^ data[3] ^ data[4] ^ data[6] ^ data[7];
    crc[27] = crcIn[1] ^ crcIn[3] ^ crcIn[4] ^ crcIn[5] ^ crcIn[7] ^ data[1] ^ data[3] ^ data[4] ^ data[5] ^ data[7];
    crc[28] = crcIn[0] ^ crcIn[4] ^ crcIn[5] ^ crcIn[6] ^ data[0] ^ data[4] ^ data[5] ^ data[6];
    crc[29] = crcIn[0] ^ crcIn[1] ^ crcIn[5] ^ crcIn[6] ^ crcIn[7] ^ data[0] ^ data[1] ^ data[5] ^ data[6] ^ data[7];
    crc[30] = crcIn[0] ^ crcIn[1] ^ crcIn[6] ^ crcIn[7] ^ data[0] ^ data[1] ^ data[6] ^ data[7];
    crc[31] = crcIn[1] ^ crcIn[7] ^ data[1] ^ data[7];
end
endfunction

`endif // CRC32_SV