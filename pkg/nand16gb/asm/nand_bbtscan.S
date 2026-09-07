@ nand_bbtscan.S - both-planes bad-block scan fix for the Whimory (WMR) NAND
@ driver, shared by disk mode, AUPD and RetailOS via --defsym.
@
@ The chip is 128-page blocks x 2 planes (plane = row[7]) and the firmware uses
@ 256-page superblocks, so superblock i is physical blocks 2i and 2i+1. A
@ factory-bad block is marked in the spare of pages 0 and 1 of the physical
@ block, but every scan type addresses pages relative to the superblock:
@
@   type 4 -> superblock pages 0,1   == physical block 2i pages 0,1
@   type 2 -> superblock page 255    == physical block 2i+1 page 127
@   type 1 -> superblock pages 0,255
@
@ so no type ever reads block 2i+1's pages 0/1. A bad block in an odd position
@ whose even partner is good is invisible, and the FTL programs a superblock
@ that cannot hold data. This chip escapes it by luck - its only odd bad block,
@ 91, is paired with an also-bad 90.
@
@ Type 4's two reads become four: superblock pages 0, 1, ppb/2 and ppb/2+1, i.e.
@ pages 0 and 1 of both halves. Any non-0xFF spare[0] marks the superblock bad.
@ Each exit branches back into the original function so its epilogue runs.
@
@ Live at the hook, from the function prologue:
@   r9 = driver globals   sl = FIL struct   fp = bank
@   r6 = block            r7 = &data buf    r4 = &spare buf   r5 = bad-block out
@ globals+6 = pages per block; the FIL's no-ECC read is *(*(sl+0xc)+8), called
@ as read(bank, row, data, spare) -> 0 on success. lr is dead here.

        .syntax unified
        .arm
        .text

@ --- address parameterisation (--defsym) -------------------------------------
@ RDERR/BAD/GOOD are required, with no fallback value; disk mode, AUPD and
@ RetailOS each supply their own. Everything else here is register layout, which
@ is the same in every build.
@
@ RDERR - read-error path (returns 0)
@ BAD   - mark bad; return 1
@ GOOD  - return 1

        .global tramp_bbt4
        .type   tramp_bbt4, %function
tramp_bbt4:
        push    {r8, lr}                @ 8 bytes: keeps sp 8-byte aligned for the call
        mov     r8, #0                  @ idx 0..3
.Lbbt_loop:
        ldrh    r0, [r9, #6]            @ r0 = pagesPerBlock
        mul     r1, r6, r0              @ r1 = block * ppb  (superblock base row)
        cmp     r8, #2
        movlo   r3, #0                  @ idx 0,1 -> even half (plane 0)
        movhs   r3, r0, lsr #1          @ idx 2,3 -> +ppb/2 = odd half's page 0
        add     r1, r1, r3
        and     r2, r8, #1              @ page 0 or 1 within that half
        add     r1, r1, r2
        ldr     r3, [r4]                @ spare buffer
        ldr     r2, [r7]                @ data buffer
        ldr     r0, [sl, #12]
        ldr     ip, [r0, #8]            @ FIL read without ECC
        mov     r0, fp                  @ bank
        blx     ip
        cmp     r0, #0
        bne     .Lbbt_err               @ read failed -> original error path
        ldr     r0, [r4]
        ldrb    r0, [r0]                @ spare[0]
        cmp     r0, #255
        bne     .Lbbt_bad               @ marker present -> superblock is bad
        add     r8, r8, #1
        @ 4 reads for a 256-page superblock; only 2 make sense at 128 pages
        ldrh    r0, [r9, #6]
        cmp     r0, #128
        movls   ip, #2
        movhi   ip, #4
        cmp     r8, ip
        blo     .Lbbt_loop
        pop     {r8, lr}
        ldr     pc, =GOOD
.Lbbt_bad:
        pop     {r8, lr}
        ldr     pc, =BAD
.Lbbt_err:
        pop     {r8, lr}
        ldr     pc, =RDERR
        .ltorg
        .size   tramp_bbt4, .-tramp_bbt4
