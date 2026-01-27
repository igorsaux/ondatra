OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 16M
}

STACK_SIZE = 64K;

SECTIONS {
    .text : {
        *(.text.start)
        *(.text .text.*)
    } > RAM

    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > RAM

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
        __global_pointer$ = . + 0x800;
    } > RAM

    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        __bss_end = .;
    } > RAM

    . = ALIGN(16);
    __stack_bottom = .;
    . += STACK_SIZE;
    __stack_top = .;

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
    }
}
