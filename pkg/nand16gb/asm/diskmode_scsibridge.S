@ diskmode_scsibridge.S - 4K<->8K SCSI/NAND bridge for iPod Nano 3G disk mode.
@ Disk-mode only; RetailOS's equivalent is osos_blockbridge.S, which cannot
@ share this code (different hook sites, arg counts and return convention).
@
@ The SCSI executors speak 4 KiB logical sectors; with a 16 GB part the NAND and
@ FTL speak 8 KiB pages. These two functions take over the SCSI read and write
@ bridges: one 8 KiB NAND page is two 4 KiB SCSI sectors.
@
@ ABI, matching the functions they replace:
@   read  : void f(lun r0, buf_ptr r1, scsi_lba r2, scsi_count r3)
@   write : void f(lun r0, buf_ptr r1, scsi_lba r2, scsi_count r3, mode [sp])
@   buf    = *buf_ptr,  target = (mode != 0) ? *(lun+8) : *(lun+4)
@   vtable = *(target), write_fn = vtable[0], read_fn = vtable[1]
@   inner call: fn(target, buf, page_lba, page_count, 0)   (5th arg on stack)
@
@ The 8 KiB page-RMW scratch is allocated lazily on first use and cached in
@ scratch_ptr. Assembled at a fixed VA; only the two branch hooks depend on it.

        .syntax unified
        .arm
        .text

        .equ    UI_ACTIVITY,    0x080155e4   @ set the disk activity indicator (kind, mode)
        .equ    MALLOC_GENERAL, 0x08019070   @ general allocator (size, kind)
        .equ    SCRATCH_KIND,   3            @ memory kind, matching USB MSC init
        .equ    HALF,           0x1000        @ 4 KiB SCSI sector
        .equ    PAGE,           0x2000        @ 8 KiB NAND page
        @ CAP_RESERVE (top-of-capacity reserve, in 8K pages) comes from the
        @ caller via --defsym, no fallback: forgetting it is an assembly error
        @ instead of a silently wrong default.

@ tramp_read - replaces the SCSI read bridge.
@ r0=lun  r1=buf_ptr  r2=scsi_lba  r3=scsi_count
        .global tramp_read
        .type   tramp_read, %function
tramp_read:
        push    {r4-r10, lr}             @ 8 regs -> sp stays 8-byte aligned
        ldr     r4, [r1]                 @ r4 = buf       = *buf_ptr
        mov     r5, r2                   @ r5 = scsi_lba
        mov     r6, r3                   @ r6 = scsi_count
        ldr     r7, [r0, #4]             @ r7 = target
        ldr     r2, [r7]                 @ vtable
        ldr     r8, [r2, #4]             @ r8 = read_fn   = vtable[1]
        mov     r9, #0                   @ r9 = status accumulator (0 = OK)
        mov     r0, #0
        mov     r1, #0
        ldr     r2, =UI_ACTIVITY
        blx     r2                       @ disk activity on

        @ ---- head: scsi_lba odd -> wanted 4K is the upper half of a page ----
        tst     r5, #1
        beq     .Lrd_body
        bl      get_scratch              @ r0 = scratch
        sub     sp, sp, #8               @ 5th arg slot (keep 8-byte align)
        mov     r1, #0
        str     r1, [sp]
        mov     r1, r0                   @ buf = scratch
        mov     r0, r7
        lsr     r2, r5, #1               @ page = lba>>1
        mov     r3, #1
        blx     r8                       @ read(target, scratch, page, 1, 0)
        orr     r9, r9, r0               @ accumulate inner status
        add     sp, sp, #8
        bl      get_scratch              @ copy scratch+HALF -> buf
        add     r1, r0, #HALF
        mov     r0, r4
        bl      copy_half
        add     r4, r4, #HALF
        add     r5, r5, #1
        subs    r6, r6, #1
        beq     .Lrd_end

.Lrd_body:                               @ ---- body: aligned even-count fast path ----
        lsrs    r3, r6, #1               @ body_pages = count>>1
        beq     .Lrd_tail
        sub     sp, sp, #8
        mov     r0, #0
        str     r0, [sp]
        mov     r0, r7
        mov     r1, r4                   @ straight into caller's buffer
        lsr     r2, r5, #1
        blx     r8                       @ read(target, buf, page, body_pages, 0)
        orr     r9, r9, r0               @ accumulate inner status
        add     sp, sp, #8
        lsr     r3, r6, #1               @ recompute (call clobbered r3)
        add     r4, r4, r3, lsl #13      @ buf += body_pages * PAGE
        add     r5, r5, r3, lsl #1       @ lba += body_pages * 2
        sub     r6, r6, r3, lsl #1       @ count -= body_pages * 2

.Lrd_tail:                               @ ---- tail: one 4K left, lower half of a page ----
        cmp     r6, #0
        beq     .Lrd_end
        bl      get_scratch
        sub     sp, sp, #8
        mov     r1, #0
        str     r1, [sp]
        mov     r1, r0                   @ buf = scratch
        mov     r0, r7
        lsr     r2, r5, #1
        mov     r3, #1
        blx     r8                       @ read(target, scratch, page, 1, 0)
        orr     r9, r9, r0               @ accumulate inner status
        add     sp, sp, #8
        bl      get_scratch              @ copy scratch -> buf
        mov     r1, r0
        mov     r0, r4
        bl      copy_half
.Lrd_end:
        mov     r0, r9                   @ return accumulated status (0 = OK)
        pop     {r4-r10, pc}
        .size   tramp_read, .-tramp_read

@ tramp_write - replaces the SCSI write bridge.
@ r0=lun  r1=buf_ptr  r2=scsi_lba  r3=scsi_count  [sp]=mode
        .global tramp_write
        .type   tramp_write, %function
tramp_write:
        push    {r4-r10, lr}             @ 8 regs -> sp 8-byte aligned
        ldr     r10, [sp, #32]           @ mode (8*4 bytes pushed)
        ldr     r4, [r1]                 @ buf
        mov     r5, r2                   @ scsi_lba
        mov     r6, r3                   @ scsi_count
        cmp     r10, #0
        ldrne   r7, [r0, #8]             @ target for mode != 0
        ldreq   r7, [r0, #4]             @ target for mode == 0
        ldr     r2, [r7]                 @ vtable
        ldr     r9, [r2]                 @ r9 = write_fn = vtable[0]
        ldr     r8, [r2, #4]             @ r8 = read_fn  = vtable[1]
        mov     r0, #1
        mov     r1, r10
        ldr     r2, =UI_ACTIVITY
        blx     r2                       @ disk activity on
        mov     r10, #0                  @ reuse r10 (mode done) as status accumulator

        @ ---- head RMW: read 8K, splice upper 4K, write 8K ----
        tst     r5, #1
        beq     .Lwr_body
        bl      get_scratch
        sub     sp, sp, #8
        mov     r1, #0
        str     r1, [sp]
        mov     r1, r0                   @ scratch
        mov     r0, r7
        lsr     r2, r5, #1
        mov     r3, #1
        blx     r8                       @ read
        orr     r10, r10, r0             @ accumulate inner status
        add     sp, sp, #8
        bl      get_scratch              @ copy buf -> scratch+HALF
        add     r0, r0, #HALF
        mov     r1, r4
        bl      copy_half
        bl      get_scratch
        sub     sp, sp, #8
        mov     r1, #0
        str     r1, [sp]
        mov     r1, r0                   @ scratch
        mov     r0, r7
        lsr     r2, r5, #1
        mov     r3, #1
        blx     r9                       @ write
        orr     r10, r10, r0             @ accumulate inner status
        add     sp, sp, #8
        add     r4, r4, #HALF
        add     r5, r5, #1
        subs    r6, r6, #1
        beq     .Lwr_end

.Lwr_body:                               @ ---- body: aligned 8K writes pass through ----
        lsrs    r3, r6, #1
        beq     .Lwr_tail
        sub     sp, sp, #8
        mov     r0, #0
        str     r0, [sp]
        mov     r0, r7
        mov     r1, r4
        lsr     r2, r5, #1
        blx     r9                       @ write(target, buf, page, body_pages, 0)
        orr     r10, r10, r0             @ accumulate inner status
        add     sp, sp, #8
        lsr     r3, r6, #1
        add     r4, r4, r3, lsl #13
        add     r5, r5, r3, lsl #1
        sub     r6, r6, r3, lsl #1

.Lwr_tail:                               @ ---- tail RMW: read 8K, splice lower 4K, write 8K ----
        cmp     r6, #0
        beq     .Lwr_end
        bl      get_scratch
        sub     sp, sp, #8
        mov     r1, #0
        str     r1, [sp]
        mov     r1, r0                   @ scratch
        mov     r0, r7
        lsr     r2, r5, #1
        mov     r3, #1
        blx     r8                       @ read
        orr     r10, r10, r0             @ accumulate inner status
        add     sp, sp, #8
        bl      get_scratch              @ copy buf -> scratch
        mov     r1, r4
        bl      copy_half
        bl      get_scratch
        sub     sp, sp, #8
        mov     r1, #0
        str     r1, [sp]
        mov     r1, r0                   @ scratch
        mov     r0, r7
        lsr     r2, r5, #1
        mov     r3, #1
        blx     r9                       @ write
        orr     r10, r10, r0             @ accumulate inner status
        add     sp, sp, #8
.Lwr_end:
        mov     r0, r10                  @ return accumulated status (0 = OK)
        pop     {r4-r10, pc}
        .size   tramp_write, .-tramp_write

@ tramp_lba_count - replaces the SCSI LBA-count bridge. r0 = lun. The
@ page-parameter calculation already stores capacity as total_pages << 1, i.e.
@ in 4 KiB sectors, so doubling again here would over-report capacity 2x.
        .global tramp_lba_count
        .type   tramp_lba_count, %function
tramp_lba_count:
        @ The inner count comes back as a broken tiny value (5 blocks), so
        @ compute capacity from the driver globals instead.
        ldr     r0, =0x08050900          @ driver globals
        ldr     r0, [r0, #0x30]          @ user page count (0x1E4000 for this 16GB part)
        ldr     r1, =CAP_RESERVE         @ gross geometry: the FTL keeps the top hyperblocks
        sub     r0, r0, r1               @ as GC over-provision, so those pages medium-error.
                                         @ 0x800 was too small; failures reached 2107 pages down.
        lsl     r0, r0, #1               @ * 2 -> 4 KiB sectors
        bx      lr
        .size   tramp_lba_count, .-tramp_lba_count

@ get_scratch: return the cached 8 KiB scratch buffer in r0, allocating it once
@ on first call. Clobbers r0-r3,r12; preserves r4-r11.
        .type   get_scratch, %function
get_scratch:
        ldr     r1, =scratch_ptr
        ldr     r0, [r1]
        cmp     r0, #0
        bxne    lr                       @ already allocated
        push    {r4, lr}
        mov     r4, r1                   @ save &scratch_ptr
        mov     r0, #PAGE
        mov     r1, #SCRATCH_KIND
        ldr     r12, =MALLOC_GENERAL
        blx     r12
        @ Use the uncached alias of the buffer so the CPU memcpy and the NAND
        @ controller DMA stay coherent without explicit d-cache maintenance.
        orr     r0, r0, #0x80000000
        str     r0, [r4]                 @ cache for next time
        pop     {r4, pc}
        .size   get_scratch, .-get_scratch

@ copy_half: copy HALF (0x1000) bytes, r0=dst r1=src. Clobbers r0-r3 only,
@ so the trampolines' state in r4-r10 survives.
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

/* tramp_d00_clr: sequential-read hook replacing the literal load that stages
 * the read microcode address (R4 is already the FMC base there). Clears
 * FMC[0xD00], left at 0x80000 by the write path, so the read doesn't enter a
 * mode that drops rows >= 64, then returns the address the replaced load would
 * have produced.
 *
 * Currently unhooked. Kept because its 20 bytes are part of the reference image
 * the shipping patchset's SHA1 was taken over. */
        .arm
        .align  2
        .global tramp_d00_clr
tramp_d00_clr:
        mov     r0, #0
        str     r0, [r4, #0xd00]    @ undo the write path's 0x80000
        ldr     r0, =0x22000b38     @ read microcode address, as the replaced load gave
        bx      lr
        .ltorg
