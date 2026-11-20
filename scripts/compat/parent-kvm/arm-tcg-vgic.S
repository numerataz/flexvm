// SPDX-License-Identifier: Apache-2.0
// Configure GICv3 at the nested VMM’s addresses and report SPI 3 from EL1.
.text
    adr x4, .
    str x0, [x4, #272]
    movz x5, #0x4000, lsl #16
    movz x6, #0x3fff, lsl #16
    movz x7, #0x3ffd, lsl #16
    movz x8, #0x3ffb, lsl #16
    movz x9, #0xffe8
    ldr w0, [x6, x9]
    ldr w1, [x7, x9]
    ldr w2, [x8, x9]
    str w0, [x4, #256]
    str w1, [x4, #260]
    str w2, [x4, #264]
    mov w0, #8
    str w0, [x6, #0x84]
    str w0, [x6, #0x104]
    mov w0, #0x80
    str w0, [x6, #0xc08]
    mov w0, #2
    str w0, [x6]
    mov x0, #1
    msr icc_sre_el1, x0
    msr icc_igrpen1_el1, x0
    mov x0, #0xff
    msr icc_pmr_el1, x0
    msr vbar_el1, x4
    msr spsel, #1
    isb
    str wzr, [x5, #4100]
    msr daifclr, #2
1:  wfi
    b 1b

irq:
    mrs x0, icc_iar1_el1
    msr icc_eoir1_el1, x0
    str w0, [x5, #4104]
    eret

.org 0x100
    .word 0, 0, 0
.org 0x280
    b irq
