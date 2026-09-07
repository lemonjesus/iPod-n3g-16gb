@ osos_blockbridge.S - 4K<->8K storage bridge for iPod Nano 3G RetailOS.
@ RetailOS only; disk mode's equivalent is diskmode_scsibridge.S, which cannot
@ share this code (different hook sites, arg counts and return convention).
@
@ Apple's translator computes `ratio = 4096 / pageSize` and multiplies lba and
@ count by it, which only works for pages smaller than 4096. An 8 KiB page gives
@ ratio 0 and every request becomes 0 blocks at LBA 0. These trampolines replace
@ the multiply with a real translation: one 8 KiB FTL page is two 4 KiB blocks.
@
@ Raising the 4096 instead does not work: the block size flows out through the
@ lun and the media and device vtables, and the MBR/APM parse and the firmware
@ volume reader address the media with it. At 8192 osos looks for the volume at
@ 63*8192 while disk mode wrote it and the EFI reads it at 63*4096.
@
@ Entered by `b` over the first `mul`, so the host frame is untouched:
@   r4 = lba   r5 = count   r6 = buf   [sp,#0] = FTL page size (unused)
@ Exits by branching to the host epilogue, which pops the return address, so lr
@ is never touched. Inner ABI: read/write(obj, pageLba, pageCount, buf) at
@ vtable [+0xc]/[+0x10], obj and vtable from OSOS_BLK_PAIR ([+0]=vtable,
@ [+4]=obj).
@
@ PAGE == 2 * HALF is baked in; on a 4 KiB chip stock is already correct.

        .syntax unified
        .arm
        .text

        .equ    HALF,           0x1000   @ one logical block
        .equ    PAGE,           0x2000   @ one FTL page == two logical blocks

@ accum_status - fold one inner call's r0 into the accumulator r9. Not
@ `orr r9,r9,r0`: r0 is 0 or an error code, and a split request makes up to
@ three calls, so OR-ing two codes can produce a third that is neither
@ (0x12 | 0x11 = 0x13). First nonzero wins.
        .macro  accum_status
        cmp     r9, #0
        moveq   r9, r0
        .endm

@ tramp_osos_read - replaces the multiply in the read executor.
@ in:  r4=lba r5=count r6=buf   out: branches to OSOS_RD_RET
        .global tramp_osos_read
        .type   tramp_osos_read, %function
tramp_osos_read:
        push    {r4-r10, lr}             @ 8 regs -> sp keeps its 8-byte align
        mov     r0, r4                   @ shuffle into our own register roles
        mov     r1, r5
        mov     r4, r6                   @ r4 = buf      (advances)
        mov     r5, r0                   @ r5 = lba      (advances)
        mov     r6, r1                   @ r6 = count    (remaining)
        ldr     r0, =OSOS_BLK_PAIR
        ldr     r3, [r0]                 @ vtable
        ldr     r7, [r0, #4]             @ r7 = obj
        ldr     r8, [r3, #0xc]           @ r8 = read
        mov     r9, #0                   @ r9 = status accumulator (0 = OK)

        @ Zero-length must do nothing: otherwise an odd lba runs the head, the
        @ `subs r6,r6,#1` underflows to 0xffffffff and the body reads
        @ 0x7fffffff pages into the caller's buffer.
        cmp     r6, #0
        beq     .Lrd_end

        @ ---- head: odd lba -> the wanted 4K is the UPPER half of a page ----
        tst     r5, #1
        beq     .Lrd_body
        bl      get_scratch
        cmp     r0, #0
        beq     .Lrd_fail                @ no scratch -> fail, never DMA to 0
        mov     r3, r0                   @ buf = scratch
        mov     r0, r7
        lsr     r1, r5, #1               @ page = lba >> 1
        mov     r2, #1
        blx     r8
        accum_status
        bl      get_scratch
        add     r1, r0, #HALF            @ src = scratch + HALF
        mov     r0, r4                   @ dst = caller buf
        bl      copy_half
        add     r4, r4, #HALF
        add     r5, r5, #1
        subs    r6, r6, #1
        beq     .Lrd_end

.Lrd_body:                               @ ---- body: whole pages, straight through ----
        lsrs    r2, r6, #1               @ pages = count >> 1
        beq     .Lrd_tail
        mov     r0, r7
        lsr     r1, r5, #1
        mov     r3, r4                   @ read directly into the caller's buffer
        blx     r8
        accum_status
        lsr     r2, r6, #1               @ recompute: the call clobbered r2
        add     r4, r4, r2, lsl #13      @ buf   += pages * PAGE
        add     r5, r5, r2, lsl #1       @ lba   += pages * 2
        sub     r6, r6, r2, lsl #1       @ count -= pages * 2

.Lrd_tail:                               @ ---- tail: one 4K left, LOWER half of a page ----
        cmp     r6, #0
        beq     .Lrd_end
        bl      get_scratch
        cmp     r0, #0
        beq     .Lrd_fail                @ no scratch -> fail, never DMA to 0
        mov     r3, r0
        mov     r0, r7
        lsr     r1, r5, #1
        mov     r2, #1
        blx     r8
        accum_status
        bl      get_scratch
        mov     r1, r0                   @ src = scratch
        mov     r0, r4
        bl      copy_half
        b       .Lrd_end
.Lrd_fail:
        mvn     r9, #0                   @ 0xffffffff - unambiguous failure
.Lrd_end:
        mov     r0, r9
        pop     {r4-r10, lr}
        b       OSOS_RD_RET              @ the outer ldmia pops the real return address
        .size   tramp_osos_read, .-tramp_osos_read

@ tramp_osos_write - replaces the multiply in the write executor. Head and tail
@ are read-modify-write: a partial page must not destroy the half the caller did
@ not supply.
@ in:  r4=lba r5=count r6=buf   out: branches to OSOS_WR_RET
        .global tramp_osos_write
        .type   tramp_osos_write, %function
tramp_osos_write:
        push    {r4-r10, lr}
        mov     r0, r4
        mov     r1, r5
        mov     r4, r6                   @ buf
        mov     r5, r0                   @ lba
        mov     r6, r1                   @ count
        ldr     r0, =OSOS_BLK_PAIR
        ldr     r3, [r0]
        ldr     r7, [r0, #4]             @ obj
        ldr     r8, [r3, #0xc]           @ read  (needed for the RMW halves)
        ldr     r10, [r3, #0x10]         @ write
        mov     r9, #0

        @ Zero-length must do nothing - see the read side. Here the same
        @ underflow writes 0x7fffffff pages and destroys the device.
        cmp     r6, #0
        beq     .Lwr_end

        @ ---- head RMW: read the page, splice the upper 4K, write it back ----
        tst     r5, #1
        beq     .Lwr_body
        bl      get_scratch
        cmp     r0, #0
        beq     .Lwr_fail                @ no scratch -> fail, never DMA to 0
        mov     r3, r0
        mov     r0, r7
        lsr     r1, r5, #1
        mov     r2, #1
        blx     r8
        accum_status
        bl      get_scratch
        add     r0, r0, #HALF            @ dst = scratch + HALF
        mov     r1, r4                   @ src = caller buf
        bl      copy_half
        bl      get_scratch
        mov     r3, r0
        mov     r0, r7
        lsr     r1, r5, #1
        mov     r2, #1
        blx     r10
        accum_status
        add     r4, r4, #HALF
        add     r5, r5, #1
        subs    r6, r6, #1
        beq     .Lwr_end

.Lwr_body:                               @ ---- body: whole pages pass through ----
        lsrs    r2, r6, #1
        beq     .Lwr_tail
        mov     r0, r7
        lsr     r1, r5, #1
        mov     r3, r4
        blx     r10
        accum_status
        lsr     r2, r6, #1
        add     r4, r4, r2, lsl #13
        add     r5, r5, r2, lsl #1
        sub     r6, r6, r2, lsl #1

.Lwr_tail:                               @ ---- tail RMW: splice the lower 4K ----
        cmp     r6, #0
        beq     .Lwr_end
        bl      get_scratch
        cmp     r0, #0
        beq     .Lwr_fail                @ no scratch -> fail, never DMA to 0
        mov     r3, r0
        mov     r0, r7
        lsr     r1, r5, #1
        mov     r2, #1
        blx     r8
        accum_status
        bl      get_scratch
        mov     r1, r4                   @ dst = scratch, src = caller buf
        bl      copy_half
        bl      get_scratch
        mov     r3, r0
        mov     r0, r7
        lsr     r1, r5, #1
        mov     r2, #1
        blx     r10
        accum_status
        b       .Lwr_end
.Lwr_fail:
        mvn     r9, #0                   @ 0xffffffff - unambiguous failure
.Lwr_end:
        mov     r0, r9
        pop     {r4-r10, lr}
        b       OSOS_WR_RET
        .size   tramp_osos_write, .-tramp_osos_write

@ get_scratch: the 8 KiB RMW page, returned in r0. Clobbers r0-r3,r12 only.
@ OSOS_SCRATCH is a static reservation inside the image, not an allocation: a
@ failed DMA alloc returns 0, and address 0 is the SRAM alias holding the
@ exception vector table, so a null DMA target silently overwrites the vectors
@ instead of faulting. First call 32-byte aligns it, cleans those lines and
@ switches to the 0x80000000 uncached alias; cached in scratch_ptr after.
        .type   get_scratch, %function
get_scratch:
        ldr     r1, =scratch_ptr
        ldr     r0, [r1]
        cmp     r0, #0
        bxne    lr                       @ already prepared
        push    {r4, r5, r6, lr}
        mov     r4, r1                   @ r4 = &scratch_ptr
        ldr     r0, =OSOS_SCRATCH        @ static reservation, never fails
        add     r0, r0, #0x1f
        bic     r0, r0, #0x1f            @ 32-byte align
        mov     r5, r0
        tst     r5, #0x08000000          @ cached DRAM pointer?
        beq     .Lgs_store
        mov     r0, r5
        mov     r1, #PAGE
        ldr     r12, =OSOS_CACHE_CLEAN
        blx     r12
        orr     r5, r5, #0x80000000      @ switch to the uncached alias
.Lgs_store:
        mov     r0, r5
        str     r0, [r4]
        pop     {r4, r5, r6, pc}
        .size   get_scratch, .-get_scratch

@ tramp_bitmap_alloc - replaces the DMA allocation call in the bitmap
@ constructor, which never checks the result before memset-clearing it. On an
@ exhausted pool the clear becomes memset(0, 0, 8192) over the exception vector
@ table (address 0 is the SRAM alias) and the next interrupt data-aborts
@ forever. On failure this zeroes the caller's nbits (r5, live across the call
@ by AAPCS), so the clear computes 0 bytes and writes nothing. A defect on stock
@ too, just unreachable there.
        .global tramp_bitmap_alloc
        .type   tramp_bitmap_alloc, %function
tramp_bitmap_alloc:
        push    {lr}
        ldr     r12, =OSOS_ALLOC_DMA
        blx     r12                      @ r0 = buffer, or 0 on failure
        cmp     r0, #0
        moveq   r5, #0                   @ failed -> nbits = 0 -> clear writes 0 bytes
        pop     {pc}
        .size   tramp_bitmap_alloc, .-tramp_bitmap_alloc

@ tramp_bitmap_store - null-guard the set-bit accessor's one store; a NULL
@ bitmap->data from an exhausted pool otherwise corrupts the vector table one
@ bit at a time. Set and clear arms converge here, so one guard covers both.
@ In: r0=data r1=value r5=word index. Returns by replicating the stock epilogue
@ (not a branch target elsewhere). Popcount at [r4,#4] keeps stock's off-by-one,
@ deliberately unchanged here.
        .global tramp_bitmap_store
        .type   tramp_bitmap_store, %function
tramp_bitmap_store:
        cmp     r0, #0
        strne   r1, [r0, r5, lsl #2]     @ store only if data is non-NULL
        ldmia   sp!, {r4, r5, r6, pc}    @ the accessor's own epilogue
        .size   tramp_bitmap_store, .-tramp_bitmap_store

@ copy_half: copy HALF bytes, r0=dst r1=src. Clobbers r0-r3 only.
        .type   copy_half, %function
copy_half:
        mov     r2, #HALF
.Lcopy_loop:
        ldr     r3, [r1], #4
        str     r3, [r0], #4
        subs    r2, r2, #4
        bne     .Lcopy_loop
        bx      lr
        .size   copy_half, .-copy_half

        .ltorg
        .align  2
scratch_ptr:
        .word   0
