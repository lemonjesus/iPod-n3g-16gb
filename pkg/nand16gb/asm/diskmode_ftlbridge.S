@ diskmode_ftlbridge.S - the 4K<->8K scratch-RMW fix on disk mode's FTL
@ read/write path. Disk mode only.
@
@ The stock conversion is `r0 = 4096/pageSize; lpn = r0*arg1; count = r0*arg2`,
@ which gives count = 0 for any odd arg2 on this 8K-page part. These two
@ trampolines replace it with a per-4K-sector loop: each sector is one half of
@ an 8K FTL page, so we read or write the full page through an 8K scratch and
@ copy the 4K half.
@   tramp_ftl_rd: read the 8K page into scratch, copy the half into buf
@   tramp_ftl_wr: blank the scratch, read the 8K page back into it, splice the
@                 4K from buf, write the 8K back
@ Inputs at the hook: r4 = sector, r5 = sector count, r6 = buf. The host buffer
@ is exactly count*4096 bytes, so we never overflow. Each trampoline returns
@ via the host function's own epilogue, which restores r4-r7; r8-r11 we
@ preserve ourselves.
        .syntax unified
        .arm
        .text

        .equ    FTL_MALLOC, 0x08019070      @ general allocator (size, kind)

@ get_ftl_scratch: r0 = cached 8K scratch (malloc'd once). clobbers r0-r3,r12.
        .type   get_ftl_scratch, %function
get_ftl_scratch:
        ldr     r12, =ftl_scr
        ldr     r0, [r12]
        cmp     r0, #0
        bxne    lr
        push    {r4, lr}
        mov     r4, r12
        mov     r0, #0x2000             @ 8192 (one 8K scratch page)
        mov     r1, #3                  @ memory_kind
        ldr     r12, =FTL_MALLOC
        blx     r12
        orr     r0, r0, #0x80000000     @ uncached alias (DMA coherency)
        str     r0, [r4]
        pop     {r4, pc}

        .global tramp_ftl_rd
        .type   tramp_ftl_rd, %function
tramp_ftl_rd:
        orr     r12, r4, r5             @ aligned (arg1 even AND arg2 even)?
        tst     r12, #1
        bne     .Lrd_rmw
        @ aligned fast path: one batched page read fills buf directly, which is
        @ byte for byte the read the stock build issues.
        mov     r1, r4, lsr #1          @ page  = arg1 >> 1
        mov     r2, r5, lsr #1          @ count = arg2 >> 1 (pages)
        mov     r3, r6                  @ buf
        ldr     r0, =0x0802ec68
        ldr     r0, [r0]
        ldr     r12, [r0, #0]
        ldr     r12, [r12, #0xc]        @ FTL read
        ldr     r0, [r0, #4]            @ ctx
        blx     r12                     @ r4/r5/r6 preserved across the read
        ldr     r12, =0x0802ec64        @ host function epilogue
        bx      r12
.Lrd_rmw:
        push    {r8, r9, r10, r11}
        bl      get_ftl_scratch
        mov     r7, r0                  @ r7 = scratch (r7 restored by fn epilogue)
        ldr     r0, =0x0802ec68
        ldr     r0, [r0]                @ FTL global
        ldr     r1, [r0, #0]            @ struct
        ldr     r8, [r1, #0xc]          @ r8 = FTL read
        ldr     r9, [r0, #4]            @ r9 = ctx
        mov     r10, #0                 @ r10 = i
.Lrd_loop:
        cmp     r10, r5
        bhs     .Lrd_done
        add     r11, r4, r10            @ sec = arg1 + i
        mov     r0, r9                  @ ctx
        mov     r1, r11, lsr #1         @ page = sec >> 1
        mov     r2, #1                  @ count = 1 page
        mov     r3, r7                  @ scratch
        blx     r8                      @ read 8K page into scratch
        and     r0, r11, #1             @ half = sec & 1
        mov     r0, r0, lsl #12         @ half * 4096
        add     r1, r7, r0              @ src = scratch + half*4096
        mov     r0, r10, lsl #12        @ i * 4096
        add     r0, r6, r0              @ dst = buf + i*4096
        orr     r0, r0, #0x80000000     @ uncached: CPU writes physical for the USB DMA
        mov     r2, #0x1000
.Lrd_cpy:
        ldr     r12, [r1], #4
        str     r12, [r0], #4
        subs    r2, r2, #4
        bne     .Lrd_cpy
        add     r10, r10, #1
        b       .Lrd_loop
.Lrd_done:
        pop     {r8, r9, r10, r11}
        mov     r0, #0
        ldr     r12, =0x0802ec64        @ host function epilogue
        bx      r12

        .global tramp_ftl_wr
        .type   tramp_ftl_wr, %function
tramp_ftl_wr:
        orr     r12, r4, r5             @ aligned (arg1 even AND arg2 even)?
        tst     r12, #1
        bne     .Lwr_rmw
        @ aligned fast path: one batched page write, no per-sector RMW (no 2x amp)
        mov     r1, r4, lsr #1          @ page  = arg1 >> 1
        mov     r2, r5, lsr #1          @ count = arg2 >> 1 (pages)
        mov     r3, r6                  @ buf
        ldr     r0, =0x0802ecc0
        ldr     r0, [r0]
        ldr     r12, [r0, #0]
        ldr     r12, [r12, #0x10]       @ FTL write
        ldr     r0, [r0, #4]            @ ctx
        blx     r12
        ldr     r12, =0x0802ecbc        @ host function epilogue
        bx      r12
.Lwr_rmw:
        push    {r8, r9, r10, r11}
        bl      get_ftl_scratch
        mov     r7, r0                  @ r7 = scratch
        ldr     r0, =0x0802ecc0
        ldr     r0, [r0]                @ FTL global (write)
        ldr     r11, [r0, #0]           @ struct (read=[+0xc], write=[+0x10])
        ldr     r8, [r0, #4]            @ r8 = ctx
        mov     r9, #0                  @ r9 = i
.Lwr_loop:
        cmp     r9, r5
        bhs     .Lwr_done
        add     r10, r4, r9             @ sec = arg1 + i
        @ blank scratch to 0xFF (so the un-spliced half is erased on a fresh page)
        mov     r0, r7
        mvn     r1, #0
        mov     r2, #0x2000
.Lwr_clr:
        str     r1, [r0], #4
        subs    r2, r2, #4
        bne     .Lwr_clr
        @ RMW: read the existing 8K page into scratch (ignore error/unmapped)
        mov     r0, r8
        mov     r1, r10, lsr #1
        mov     r2, #1
        mov     r3, r7
        ldr     r12, [r11, #0xc]        @ read fn
        blx     r12
        @ splice: copy buf[i*4096] -> scratch[half*4096]
        and     r0, r10, #1
        mov     r0, r0, lsl #12
        add     r0, r7, r0              @ dst = scratch + half*4096
        mov     r1, r9, lsl #12
        add     r1, r6, r1              @ src = buf + i*4096
        orr     r1, r1, #0x80000000     @ uncached: read the host's USB-DMA'd data from physical
        mov     r2, #0x1000
.Lwr_cpy:
        ldr     r12, [r1], #4
        str     r12, [r0], #4
        subs    r2, r2, #4
        bne     .Lwr_cpy
        @ write the full 8K page back
        mov     r0, r8
        mov     r1, r10, lsr #1
        mov     r2, #1
        mov     r3, r7
        ldr     r12, [r11, #0x10]       @ write fn
        blx     r12
        add     r9, r9, #1
        b       .Lwr_loop
.Lwr_done:
        pop     {r8, r9, r10, r11}
        mov     r0, #0
        ldr     r12, =0x0802ecbc        @ host function epilogue
        bx      r12

        .align 2
ftl_scr:
        .word   0
        .ltorg
