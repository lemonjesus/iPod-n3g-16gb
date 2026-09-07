@ nand_planeerase.S - two-plane erase fix for the Whimory (WMR) NAND driver,
@ shared by disk mode, AUPD and RetailOS via --defsym.
@
@ The chip is 128-page blocks x 2 planes (plane = row[7]); the firmware uses
@ 256-page blocks and issues one erase at row = pbn<<8, which is plane 0 only.
@ The write path programs both planes (row and row|0x80), so firmware pages
@ 128..255 land in plane 1 while plane 1 is never erased. On a recycled block
@ plane 1 still holds the previous owner's data, the merge's plane-1 write goes
@ to non-erased pages, and the result is stale data under the wrong LPN.
@
@ The fix runs the same erase a second time for plane 1 (row|0x80). Each erase
@ path is hooked where it starts the FMISS sequencer: save the plane-0 args
@ (r0-r3), run plane 0 and wait, then on success OR 0x80 into the row buffers,
@ re-stage the FMC fields the sequencer advances ([0xd0c]/[0xd10]/[0xd18]) and
@ re-run with the same args for plane 1. Control then returns to just after the
@ original wait, so the function's own status check and return run unchanged.
@ The rows come from [0xd0c], so reusing the plane-0 args with plane-1 rows is
@ exactly a second-plane erase.

        .syntax unified
        .arm
        .text

@ --- address parameterisation (--defsym) -------------------------------------
@ All nine constants below are required, with no fallback value. Disk mode,
@ AUPD and RetailOS carry byte-identical builds of the same FIL at different
@ addresses and each supplies its own nine - see patch_diskmode.go,
@ patch_aupd.go and patch_retailos.go for the values.
@
@ NAND_RESET  - start the FMISS sequencer for the configured op
@ WAIT_CS     - wait for the CS interrupt (returns r0; 0 = timeout/error)

@ ---- sequential erase (the merge path; count = blocks per hyperblock) ------
@ At entry r0-r3 are the plane-0 args. The FMC base, globals and descriptor are
@ also live in callee-saved registers, but we reload them from literals so this
@ doesn't depend on the incoming register state.
@ SEQ_FMC_LIT  - *(SEQ_FMC_LIT)  = FMC base
@ SEQ_GAND_LIT - *(SEQ_GAND_LIT) = driver globals
@ SEQ_DESC_LIT - *(SEQ_DESC_LIT) = descriptor (row array @+4, bank array @+8)
@ SEQ_BACK     - continue after the original wait

        .global tramp_eraseseq_p1
        .type   tramp_eraseseq_p1, %function
tramp_eraseseq_p1:
        push    {r0, r1, r2, r3, r4, r5, r6, lr}   @ save the plane-0 args (r0-r3) + scratch
        @ --- plane 0 ---
        ldr     r12, =NAND_RESET
        blx     r12
        ldr     r12, =WAIT_CS
        blx     r12                       @ r0 = plane-0 result
        cmp     r0, #0
        beq     .Lseq_done                @ plane-0 errored -> skip plane 1, return r0
        @ --- plane 1: OR 0x80 into every pageArray row, reset advancing FMC regs ---
        ldr     r12, =SEQ_GAND_LIT
        ldr     r12, [r12]                @ driver globals
        ldrh    r4, [r12, #0x38]          @ r4 = count (blocks per hyperblock)
        ldr     r5, =SEQ_DESC_LIT
        ldr     r5, [r5]                  @ r5 = descriptor
        ldr     r6, [r5, #0x4]            @ r6 = row array buf
        mov     r1, #0
.Lseq_or:
        ldr     r2, [r6, r1, lsl #2]
        orr     r2, r2, #0x80             @ plane 1 select (row[7])
        str     r2, [r6, r1, lsl #2]
        add     r1, r1, #1
        cmp     r1, r4
        blo     .Lseq_or
        ldr     r12, =SEQ_FMC_LIT
        ldr     r12, [r12]                @ r12 = FMC base
        str     r6, [r12, #0xd0c]         @ re-stage the row array ptr (the sequencer advanced it)
        ldr     r0, [r5, #0x8]            @ bank array buf
        str     r0, [r12, #0xd10]
        str     r4, [r12, #0xd18]         @ count
        @ --- re-run with the saved plane-0 args, now over plane-1 rows ---
        ldr     r0, [sp, #0]
        ldr     r1, [sp, #4]
        ldr     r2, [sp, #8]
        ldr     r3, [sp, #12]
        ldr     r12, =NAND_RESET
        blx     r12
        ldr     r12, =WAIT_CS
        blx     r12                       @ r0 = plane-1 result
.Lseq_done:
        add     sp, sp, #16               @ drop the saved r0-r3
        pop     {r4, r5, r6, lr}
        ldr     r12, =SEQ_BACK
        bx      r12                       @ the original status check + return run with r0

@ ---- single erase (format/misc path; count = 1) ----------------------------
@ SGL_FMC_LIT  - as SEQ_FMC_LIT, single-block path
@ SGL_DESC_LIT - as SEQ_DESC_LIT; row buffer @ +4
@ SGL_BACK     - as SEQ_BACK, single-block path

        .global tramp_erasesingle_p1
        .type   tramp_erasesingle_p1, %function
tramp_erasesingle_p1:
        push    {r0, r1, r2, r3, r4, r5, r6, lr}
        ldr     r12, =NAND_RESET
        blx     r12
        ldr     r12, =WAIT_CS
        blx     r12                       @ r0 = plane-0 result
        cmp     r0, #0
        beq     .Lsgl_done
        @ plane 1: single row |= 0x80
        ldr     r5, =SGL_DESC_LIT
        ldr     r5, [r5]                  @ descriptor
        ldr     r6, [r5, #0x4]            @ row buffer
        ldr     r2, [r6, #0x0]
        orr     r2, r2, #0x80
        str     r2, [r6, #0x0]
        ldr     r12, =SGL_FMC_LIT
        ldr     r12, [r12]                @ FMC base
        str     r6, [r12, #0xd0c]         @ reset row ptr
        ldr     r0, [r5, #0x8]            @ bank buffer
        str     r0, [r12, #0xd10]
        mov     r0, #1
        str     r0, [r12, #0xd18]         @ count = 1
        ldr     r0, [sp, #0]
        ldr     r1, [sp, #4]
        ldr     r2, [sp, #8]
        ldr     r3, [sp, #12]
        ldr     r12, =NAND_RESET
        blx     r12
        ldr     r12, =WAIT_CS
        blx     r12                       @ r0 = plane-1 result
.Lsgl_done:
        add     sp, sp, #16
        pop     {r4, r5, r6, lr}
        ldr     r12, =SGL_BACK
        bx      r12

        .ltorg
