# A real-mode reset vector enters a flat 32-bit segment. Neither guest uses a kernel.
.code16
    cli
    lgdt %cs:gdt_pointer
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0
    ljmpl $8, $(0xf0000 + protected_mode)
.code32
protected_mode:
    mov $16, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
.if CHILD
    mov $0x80000, %ebx
    cmpl $0x11223344, (%ebx)
    jne bad
    movl $0x55667788, (%ebx)
    mov $0x10, %eax
    jmp quit
.else
    inb $0x92, %al
    orb $2, %al
    outb %al, $0x92
    mov $0x1080000, %ebx
    movl $0x11223344, (%ebx)
wait_child:
    cmpl $0x55667788, (%ebx)
    jne wait_child
    mov $0x11, %eax
    jmp quit
.endif
bad:
    mov $0x7f, %eax
quit:
    mov $0xf4, %dx
    out %eax, %dx
    hlt
    jmp quit
.balign 8
gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
gdt_end:
gdt_pointer:
    .word gdt_end - gdt - 1
    .long 0xf0000 + gdt
.org 0xfff0
.code16
    ljmp $0xf000, $0
.org 0x10000
