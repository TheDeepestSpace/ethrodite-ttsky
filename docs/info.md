<!---

This file is used to generate your project datasheet. Please fill in the information below and delete any unused
sections.

You can also include images in this folder and reference them in the markdown. Each image must be less than
512 kb in size, and the combined size of all images must be less than 1 MB.
-->

## How it works

This project is a TCP stack that takes in frames and instructions from UART and outputs the remaining network layers over UART.

## How to test

Send in ethernet frames over uart, and see what comes back

## External hardware

Obviously we have the UART that comes with this tiny tapeout, alongside that a CPU with access to ethernet and UART would be needed.