/* Free RRAM above the loader image and below KERNEL_START.
 *
 * LOADER_START  = 0x60060000   the jal we retarget lives here
 * (payload)     = 0x60090000   verified free: writing here and restoring the
 *                              header left the loader signature valid
 * KERNEL_START  = 0x60099000   offsets/common.rs:13. xous.img begins here.
 *                              Reaching it overwrites the OS and bricks the badge.
 *
 * LENGTH below is the hard ceiling. tools/elf2bin.py asserts it again, because
 * a linker overflow is an error you want twice.
 */
MEMORY
{
  PAYLOAD : ORIGIN = 0x60090000, LENGTH = 0x9000    /* 36 KiB to KERNEL_START */
  RAM     : ORIGIN = 0x61100000, LENGTH = 512K
}
ENTRY(_start)
SECTIONS
{
  .text : {
    KEEP(*(.text.entry))       /* _start MUST be the first byte at ORIGIN:  */
                               /* the retargeted jump lands exactly here    */
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > PAYLOAD

  .data : { *(.data .data.*) . = ALIGN(4); } > PAYLOAD

  .bss (NOLOAD) : {
    . = ALIGN(4); __sbss = .;
    *(.bss .bss.*) *(COMMON)
    . = ALIGN(4); __ebss = .;
  } > RAM

  _stack_top = ORIGIN(RAM) + LENGTH(RAM);
  /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) }
}
