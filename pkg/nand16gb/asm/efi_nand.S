@ efi_nand.S - the N3G EFI NAND driver's patches (PE32 file GUID
@ 945F3B55-95A5-4BD9-AEED-6EC243B813A8). EFI only.
@
@ The nand_*.S sources can't work here because the EFI is THUMB. These are
@ re-implementations of the same fixes: two-plane erase from nand_planeerase.S
@ and erased-page poison/ECC from nand_erasedpage.S, plus Block IO and BBT-scan
@ patches the EFI needs on its own.
@
@ Any hook that displaces more than 4 bytes (the three erase sites) MUST be
@ padded with nops.
@
@ NAND_GO/NAND_WAIT/ECC_REAL are only ever `bl` targets, and Thumb `bl` is
@ PC-relative, so nothing here depends on the module's load address. FMC_DESC is
@ a physical MMIO address and is absolute.
@
@ FMC registers, base 0x38a00000, at the offsets the nand_*.S trampolines use:
@   +0xc30 aggregate ECC status          +0xd18 count (blocks/erase, pages/read)
@   +0xd0c row/page array pointer        +0xd20 per-chunk DMA dest array (reads)
@   +0xd10 bank/CE array pointer         +0xd28 groups (2KB ECC chunks) per page
@ Starting the FMISS sequencer takes no register arguments: it runs off whatever
@ is staged above, and the hardware advances those fields as it works, so they
@ must be re-staged before the plane-1 retry.

        .syntax unified
        .arch   armv5te     @ ARM926EJ-S is Thumb-1 only; reject Thumb-2-only encodings
                             @ instead of silently widening them.
        .thumb
        .text

        .equ    FMC_DESC,    0x38a00d00   @ row=+0xc bank=+0x10 count=+0x18 chunks=+0x20 groups/page=+0x28
        .equ    NAND_GO,     0x40256694   @ start the FMISS sequencer
        .equ    NAND_WAIT,   0x4025671c   @ wait for the CS interrupt
        .equ    ECC_REAL,    0x40256972   @ the stock ECC check, used as the fallback
        .equ    POISON_W0,   0x88a0a0a0   @ erased-chunk ECC-garbage signature, same as disk mode's
        .equ    POISON_W1,   0x200a02a0

@ tramp_efi_erase_p1 - two-plane erase fix, shared by all three erase call
@ sites. Each site's kick/wait pair (8 bytes) becomes
@ `bl tramp_efi_erase_p1 ; nop ; nop`, so nothing else in the caller moves.
@
@ The caller has already staged FMC+0xd0c/+0xd10/+0xd18 (row array, bank array,
@ count) for plane 0. Snapshot those, run plane 0, and on success OR 0x80 into
@ every row array entry (the plane-1 select bit), re-stage and run plane 1.
@ r0 comes back as if the original wait had produced it.
        .global tramp_efi_erase_p1
        .type   tramp_efi_erase_p1, %function
        .thumb_func
tramp_efi_erase_p1:
        push    {r1, r2, r3, r4, r5, r6, r7, lr}
        ldr     r4, =FMC_DESC
        ldr     r5, [r4, #0xc]          @ r5 = row array ptr (save before the engine mutates FMC)
        ldr     r6, [r4, #0x10]         @ r6 = bank array ptr (save)
        ldr     r7, [r4, #0x18]         @ r7 = count (save)
        ldr     r0, [r4, #0x24]         @ r0 = +0x24 (save - see .Leretrig)
        push    {r0, r1}                @ no free low reg left; r1 is already saved above and
                                        @ only pairs here to keep sp 8-byte aligned (AAPCS)
        bl      NAND_GO                 @ plane 0
        bl      NAND_WAIT               @ r0 = plane-0 result (nonzero = ok)
        cmp     r0, #0
        beq     .Ledone                 @ plane-0 failed -> skip plane 1, return r0 (0)
        movs    r1, #0                  @ loop index
.Leor:
        cmp     r1, r7
        bge     .Leretrig
        lsls    r3, r1, #2
        ldr     r2, [r5, r3]
        movs    r0, #0x80               @ plane-1 select bit (row[7])
        orrs    r2, r0
        str     r2, [r5, r3]
        adds    r1, r1, #1
        b       .Leor
.Leretrig:
        str     r5, [r4, #0xc]          @ re-stage the saved FMC fields (the engine advanced these)
        str     r6, [r4, #0x10]
        str     r7, [r4, #0x18]
        ldr     r0, [sp, #0]            @ +0x24, saved on entry
        str     r0, [r4, #0x24]         @ All three erase call sites write +0x24 immediately
                                        @ before they start the FMISS sequencer, so it is part of the
                                        @ staged descriptor and has to be re-staged for plane 1
                                        @ exactly like the other three.
        bl      NAND_GO                 @ plane 1
        bl      NAND_WAIT               @ r0 = plane-1 result
.Ledone:
        add     sp, sp, #8              @ drop the stacked +0x24 / alignment pad
        pop     {r1, r2, r3, r4, r5, r6, r7, pc}

@ tramp_efi_read_go - descriptor snapshot for the ECC scrub below.
@ tramp_efi_ecc_scrub runs after the FMISS sequencer returns, and by then the
@ engine has consumed the descriptor, so the scrub cannot read count from
@ FMC+0x18 post-op - it would get whatever the engine left and disable itself.
@ Latch the three fields it needs while they are still valid, into rd_snap.
        .global tramp_efi_read_go
        .type   tramp_efi_read_go, %function
        .thumb_func
tramp_efi_read_go:
        push    {r1, r2, r3, r4, r5, lr}
        ldr     r4, =FMC_DESC
        adr     r5, rd_snap             @ PC-relative: no dependence on the load address
        ldr     r1, [r4, #0x18]         @ count (pages in this transfer)
        ldr     r2, [r4, #0x20]         @ per-chunk DMA dest array BASE, pre-advance
        ldr     r3, [r4, #0x28]         @ groups (chunks) per page
        str     r1, [r5, #0]
        str     r2, [r5, #4]
        str     r3, [r5, #8]
        bl      NAND_GO
        bl      NAND_WAIT               @ r0 = transfer result, passed back untouched
        pop     {r1, r2, r3, r4, r5, pc}

@ tramp_efi_ecc_scrub - erased-page poison/ECC fix, replacing the 4-byte call
@ to the stock ECC check in both page readers. Same calling convention as the
@ function it replaces: r0 = aggregate ECC status (FMC+0xc30), r1 = corrected-
@ bits out ptr (may be 0), r2 = single-page flag.
@
@ Does what disk mode's erased_chunk_fix does, but from the call site rather
@ than as an entry detour: the EFI's ECC check only ever sees a pre-decoded
@ scalar status, so the per-chunk walk has to happen in the caller, where
@ FMC+0xd20 is still addressable. Gated on aggregate UNCORRECTABLE with zero
@ bit-errors, walk the transfer's chunk entries (count * groups/page), scrub
@ poison-signature chunks to 0xFF and synthesize BLANK (all erased) or GOOD
@ (partial). Anything else falls through to the stock check.
@
@ The original r0/r1/r2 are pushed up front and only ever read back off the
@ stack, since the scan loop reuses r0/r2 as scratch and the ambiguous-verdict
@ exit is reached after that reuse.
        .global tramp_efi_ecc_scrub
        .type   tramp_efi_ecc_scrub, %function
        .thumb_func
tramp_efi_ecc_scrub:
        push    {r0, r1, r2, r4, r5, r6, r7, lr}
        lsls    r3, r0, #1
        bpl     .Lstock                 @ bit30 (0x40000000, UNCORRECTABLE) clear -> normal read -> stock
        lsls    r3, r0, #24
        lsrs    r3, r3, #24             @ r3 = status & 0xff (bit-error count)
        cmp     r3, #0
        bne     .Lstock                 @ real bit-errors present -> stock (never mask real corruption)
        @ Take count / dest-base / groups from the pre-kick snapshot, not from the
        @ FMC - the engine has consumed the descriptor by now (see
        @ tramp_efi_read_go). The latched base also removes the rewind arithmetic
        @ entirely, so there is no way to under- or over-rewind off the array.
        adr     r4, rd_snap
        ldr     r7, [r4, #0]            @ count (pages in this transfer)
        ldr     r5, [r4, #4]            @ per-chunk DMA dest array base
        ldr     r6, [r4, #8]            @ groups (chunks) per page
        cmp     r6, #0
        beq     .Lstock                 @ no groups -> stock
        cmp     r7, #0
        beq     .Lstock                 @ no snapshot or empty transfer -> stock
        cmp     r5, #0
        beq     .Lstock                 @ no dest array -> stock
        muls    r6, r7, r6              @ r6 = total chunks = count * groups. Both readers stage
                                        @ one descriptor covering all `count` pages, start the
                                        @ sequencer once and make one ECC call, filling the dest
                                        @ array as dest[i*groups + g] across every page. The erased
                                        @ gate is per-transfer, so the walk has to cover every page
                                        @ of a multi-page read, not just the first.
        @ Sanity clamp. Thumb-1 CMP takes only an 8-bit immediate, so build the
        @ bound in a register.
        movs    r4, #1
        lsls    r4, r4, #12             @ 4096 chunks (= 8MB of transfer; nothing legitimate is bigger)
        cmp     r6, r4
        bhi     .Lstock
        movs    r3, #0                  @ chunk index
        movs    r7, #0                  @ real_count (real / undetected chunks)
.Lloop:
        cmp     r3, r6
        bge     .Lverdict
        lsls    r4, r3, #2
        ldr     r2, [r5, r4]            @ chunk dest addr
        movs    r0, #1
        lsls    r0, r0, #31             @ 0x80000000 (uncached alias - true DMA'd bytes)
        orrs    r2, r0
        ldr     r4, [r2, #0]            @ word0
        adds    r0, r4, #1
        beq     .Lnext                  @ word0 == 0xFFFFFFFF -> already blank, not real
        ldr     r0, =POISON_W0
        cmp     r4, r0
        bne     .Lreal                  @ not poison -> real / undetected
        ldr     r4, [r2, #4]            @ word1
        ldr     r0, =POISON_W1
        cmp     r4, r0
        bne     .Lreal                  @ not poison -> real / undetected
        @ poison chunk -> scrub its 2KB to 0xFF. Borrow r3/r6 (chunk index/total,
        @ stacked here and restored after) since all other regs are committed and
        @ Thumb-1 CMP/SUBS immediates only reach 8 bits - too small for 0x800.
        push    {r3, r6}
        movs    r0, #0
        mvns    r0, r0                  @ r0 = 0xFFFFFFFF
        movs    r3, #1
        lsls    r3, r3, #9              @ r3 = 512 words (0x800 bytes / 4)
        movs    r6, #0                  @ byte offset
.Lfill:
        str     r0, [r2, r6]
        adds    r6, r6, #4
        subs    r3, r3, #1
        bne     .Lfill
        pop     {r3, r6}
        b       .Lnext
.Lreal:
        adds    r7, r7, #1
.Lnext:
        adds    r3, r3, #1
        b       .Lloop
.Lverdict:
        cmp     r7, #0
        beq     .Lblank
        cmp     r7, r6
        beq     .Lstock                 @ none detected erased -> ambiguous -> stock (never regress)
        movs    r0, #0                  @ partial page -> GOOD (deliver real chunks)
        b       .Lwriteout
.Lblank:
        @ Every chunk erased. Match what the stock check returns on a chip whose
        @ decoder sets the all-FF bit instead of poisoning: BLANK(1) only when the
        @ single-page flag is set, otherwise GOOD(0). Returning BLANK for a
        @ multi-page read would be a verdict the callers never see from stock, and
        @ the sequential reader always passes the flag as 0 anyway.
        ldr     r0, [sp, #8]            @ original r2 = single-page flag
        cmp     r0, #1
        bne     .Lgood
        movs    r0, #1                  @ single-page, all erased -> BLANK
        b       .Lwriteout
.Lgood:
        movs    r0, #0                  @ multi-page, all erased -> GOOD
.Lwriteout:
        ldr     r2, [sp, #4]            @ r2 = original r1 (corrected-bits ptr)
        cmp     r2, #0
        beq     .Lret
        movs    r4, #0
        strb    r4, [r2]                @ report zero corrected bits
.Lret:
        add     sp, sp, #12             @ drop the saved r0/r1/r2 (verdict is already in r0)
        pop     {r4, r5, r6, r7, pc}
.Lstock:
        pop     {r0, r1, r2}            @ restore original args (r4-r7/lr still saved below, untouched)
        bl      ECC_REAL                @ its result (r0) becomes ours
        pop     {r4, r5, r6, r7, pc}    @ restore scratch and return via the original entry-time lr

        .pool

@ rd_snap - the descriptor latch written by tramp_efi_read_go and read by
@ tramp_efi_ecc_scrub. Placed last so both `adr` references reach it: Thumb-1
@ ADR is forward-only, 0..1020 bytes, word-aligned.
@   [0] = count   [4] = per-chunk DMA dest array base   [8] = groups per page
        .align  2
        .global rd_snap
rd_snap:
        .word   0
        .word   0
        .word   0

@ tramp_efi_bbt_scan - factory bad-block scan that sees both planes. Same fix as
@ nand_bbtscan.S: the firmware models 4096 x 256-page superblocks over silicon
@ that is 8192 x 128-page blocks in two planes, so superblock i is physical
@ blocks 2i and 2i+1 and the stock scan only ever reads 2i's pages 0/1. Read
@ pages 0 and 1 of both halves (rows base+0, base+1, base+ppb/2, base+ppb/2+1)
@ and mark the superblock bad if any carries a marker. At 128 pages there is no
@ odd half and only the first two reads happen.
@
@ Placed after rd_snap: nothing here uses `adr`, and putting it above would push
@ rd_snap's two references out of range. The two 16-bit literal loads at the
@ hook become one 4-byte `bl`, so nothing else moves. We never return - each
@ exit branches into a stock epilogue, so sp must be exactly as it was.
@
@ Live at the hook, from the function prologue:
@   r4 = spare buffer   r5 = bad-block out ptr   r6 = block   r7 = globals
@   [sp,#0x04] = bank   [sp,#0x0c] = data buffer
@ globals+6 = pages per superblock. r6/r7 are free scratch (the epilogue pops
@ r4-r7); r5 must survive because CIB_BAD stores through it.
@
@ CIB_* are `bl` targets only, so they stay PC-relative; `bl` doubles as the
@ long jump since lr is dead and Thumb-1 `b` cannot reach that far. VFL_DATA_SLOT
@ is the one address we read rather than call, resolved via a link-time delta
@ plus `mov rX, pc` so no absolute address is baked into a register.

        .equ    VFL_DATA_SLOT, 0x40255a8c   @ literal slot holding the VFL data ptr
        .equ    CIB_BAD,       0x40255762   @ mark bad; return 1
        .equ    CIB_GOOD,      0x402557ae   @ return 1
        .equ    CIB_ERR,       0x402557b4   @ return 0 (read failed)

@ One read + marker test. Row must already be in r1. The FIL's no-ECC read is
@ (bank, row, data, spare) -> 0 on success; a factory marker shows up as a
@ non-0xFF first spare byte.
        .macro  BBT_RDCHK
        ldr     r0, [sp, #0x08]         @ bank           (sp is hook-sp - 4)
        ldr     r2, [sp, #0x10]         @ data buffer
        ldr     r2, [r2, #0x0]
        ldr     r3, [r4, #0x0]          @ spare buffer
        blx     r7                      @ read without ECC
        cmp     r0, #0x0
        beq     1f
        b       .Lbbt_err
1:      ldr     r0, [r4, #0x0]
        ldrb    r0, [r0, #0x0]          @ spare[0]
        cmp     r0, #0xff
        beq     2f
        b       .Lbbt_bad               @ marker present -> superblock is bad
2:
        .endm

        .global tramp_efi_bbt_scan
        .type   tramp_efi_bbt_scan, %function
        .thumb_func
tramp_efi_bbt_scan:
        ldrh    r0, [r7, #0x6]          @ ppb (pages per superblock)
        movs    r1, r6
        muls    r1, r0                  @ r1 = block * ppb = even half's page 0
        movs    r6, r1                  @ r6 = base row (r7 is reused below)
        ldr     r2, =VFL_DATA_SLOT      @ link-time absolute...
        ldr     r3, =.Lbbt_pc           @ ...minus the link-time absolute of the
        subs    r2, r2, r3              @ next instruction: the (unknown) load base
                                        @ cancels, leaving a pure delta. Saying
                                        @ `.word VFL_DATA_SLOT - .Lbbt_pc` directly
                                        @ is what we mean, but gas cannot emit that
                                        @ relocation (absolute minus section-relative).
        subs    r2, r2, #0x4            @ pc below reads as .Lbbt_pc + 4
.Lbbt_pc:
        mov     r3, pc                  @ r3 = .Lbbt_pc + 4
        adds    r2, r2, r3              @ r2 = &VFL_DATA_SLOT, load-address independent
        ldr     r2, [r2, #0x0]          @ VFL data
        ldr     r2, [r2, #0xc]          @ FIL function table
        ldr     r7, [r2, #0x8]          @ r7 = read without ECC
        cmp     r0, #128
        bls     .Lbbt_single            @ 128-page geometry: no second plane

        lsrs    r0, r0, #1              @ ppb/2 = pages per PHYSICAL block
        adds    r0, r0, r6              @ odd half's page 0
        push    {r0}                    @ sp -= 4; frame shape shared with .Lbbt_single
        movs    r1, r6
        BBT_RDCHK                       @ even half, page 0
        movs    r1, r6
        adds    r1, r1, #0x1
        BBT_RDCHK                       @ even half, page 1
        ldr     r1, [sp, #0x0]
        BBT_RDCHK                       @ odd half, page 0 - the blind spot
        ldr     r1, [sp, #0x0]
        adds    r1, r1, #0x1
        BBT_RDCHK                       @ odd half, page 1
        b       .Lbbt_good

.Lbbt_single:
        push    {r6}                    @ same one-word frame, so BBT_RDCHK's
        movs    r1, r6                  @ sp-relative offsets hold on both paths
        BBT_RDCHK
        movs    r1, r6
        adds    r1, r1, #0x1
        BBT_RDCHK
        @ fall through

.Lbbt_good:
        add     sp, #0x4
        bl      CIB_GOOD
.Lbbt_bad:
        add     sp, #0x4
        bl      CIB_BAD
.Lbbt_err:
        add     sp, #0x4
        bl      CIB_ERR

        .ltorg

@ tramp_efi_blockio_4k - serve 4096-byte EFI blocks out of 8192-byte NAND pages.
@
@ The EFI's Block IO layer is hardcoded to a 4096-byte block, and that stays.
@ 4096 is the addressing contract between disk mode and the EFI: disk mode
@ writes the firmware volume starting at sector 63, i.e. absolute byte 0x3F000.
@ At an 8192-byte block 0x3F000 is not expressible as an LBA at all
@ (0x3F000/8192 = 31.5) and the volume becomes unreachable no matter how
@ healthy the FTL is. So the 4K<->8K conversion lives here instead, at the one
@ boundary where the 8 KiB page meets the 4 KiB world above it - the same split
@ disk mode and RetailOS use.
@
@ The stock ReadBlocks/WriteBlocks are thin shims over the FTL:
@       numPages = BufferSize / pageSize   (and they bail unless it is exact)
@       page     = ratio * LBA             (ratio = 4096/pageSize == 0 here)
@ Both are wrong when the page is larger than the block. This trampoline
@ replaces both bodies; the driver entrypoint is separately patched so that
@ ratio = pageSize / blockSize = 2 and lbaCount = pageCount * ratio.
@
@ Arguments, set up by the stubs written over both function bodies (which keep
@ the stock PC-relative literal loads, so nothing here needs the module's
@ runtime load address):
@       r2 = LBA          r3 = 0 for read, 1 for write
@       r4 = Buffer       r5 = driver globals   (pageSize +0x0, ratio +0x4,
@       r6 = BufferSize   r7 = NAND op arg block           CPU_ARCH +0x8)
@ Returns r0 = EFI_STATUS. r5/r7 are AAPCS callee-saved and survive every call
@ made below.
@
@ Walk the request in 4 KiB blocks, preferring whole aligned pages: an even LBA
@ with >=2 blocks left reads straight into the caller's buffer with no copy.
@ An odd LBA (the volume base is sector 63, so this hits every run's first
@ block) or a trailing odd block goes through bio_scratch, copying out just the
@ requested half - at most one bounce per end of a transfer.
@
@ Sub-page writes are read-modify-written through bio_scratch rather than
@ refused with EFI_INVALID_PARAMETER. BDS marks AUPD used before launching it,
@ and that write is a single 4096-byte block; refusing it would mean the flag
@ never persists and BDS relaunches AUPD on every boot instead of reaching the
@ OS chain.
@
@ The read-modify-write is safe because bio_xfer goes through the FTL, not raw
@ NAND: the FTL programs a fresh physical page and remaps, so no live page is
@ ever partially programmed. Power loss between the read and the write-back
@ loses the page, same as any other FTL write.

        .equ    NAND_ARGS_READ,  0x4025624e   @ build the read arg block (r0=args, r1=page, r2=count, r3=buf)
        .equ    NAND_ARGS_WRITE, 0x40256254   @ same, for write
        .equ    NAND_SWITCH,     0x4025615e   @ dispatch (r0=op, r1=args)
        .equ    NAND_OP_READ,    0x65
        .equ    NAND_OP_WRITE,   0x64

        .global tramp_efi_blockio_4k
        .type   tramp_efi_blockio_4k, %function
        .align  2
tramp_efi_blockio_4k:
        push    {r4, r5, r6, r7, lr}
        sub     sp, #28
        @ frame: +0  saved isWrite across the RMW read leg (see .Lbio_partial)
        @        +12 lba   +16 dst   +20 blocks remaining   +24 isWrite
        @ bio_xfer builds its own outgoing-argument frame, so +4/+8 are spare.
        str     r3, [sp, #24]
        str     r2, [sp, #12]
        str     r4, [sp, #16]
        lsls    r0, r6, #20             @ BufferSize must be a whole 4 KiB count
        bne     .Lbio_badparam
        lsrs    r0, r6, #12
        str     r0, [sp, #20]
        b       .Lbio_loop

.Lbio_badparam:
        movs    r0, #1
        lsls    r0, r0, #31
        adds    r0, #2                  @ EFI_INVALID_PARAMETER (0x80000002)
        b       .Lbio_out
.Lbio_fail:
        movs    r0, #1
        lsls    r0, r0, #31
        adds    r0, #7                  @ EFI_DEVICE_ERROR (0x80000007)
        b       .Lbio_out
.Lbio_ok:
        movs    r0, #0
.Lbio_out:
        add     sp, #28
        pop     {r4, r5, r6, r7, pc}

.Lbio_loop:
        ldr     r0, [sp, #20]
        cmp     r0, #0
        beq     .Lbio_ok
        ldr     r1, [sp, #12]
        movs    r2, #1
        ands    r2, r1                  @ LBA odd -> must bounce
        bne     .Lbio_partial
        cmp     r0, #2                  @ <2 blocks left -> must bounce
        blo     .Lbio_partial

        @ ---- aligned run: r0>>1 whole pages straight into the caller's buffer
        lsrs    r2, r0, #1
        lsrs    r1, r1, #1
        ldr     r3, [sp, #16]
        bl      bio_xfer
        cmp     r0, #0
        bne     .Lbio_fail
        ldr     r0, [sp, #20]
        lsrs    r2, r0, #1              @ pages transferred
        lsls    r1, r2, #1              @ = blocks consumed
        subs    r0, r0, r1
        str     r0, [sp, #20]
        ldr     r0, [sp, #12]
        adds    r0, r0, r1
        str     r0, [sp, #12]
        lsls    r1, r2, #13             @ = bytes consumed
        ldr     r0, [sp, #16]
        adds    r0, r0, r1
        str     r0, [sp, #16]
        b       .Lbio_loop

.Lbio_pfail:
        b       .Lbio_fail              @ .Lbio_fail is out of Thumb-1 bcc range

.Lbio_partial:
        @ One 4 KiB block that is not a whole-page aligned run. Always read the
        @ containing 8 KiB page into bio_scratch first: a read needs it to hand
        @ back the requested half, a write needs it to preserve the other half.
        ldr     r0, [sp, #24]
        str     r0, [sp, #0]            @ save isWrite ...
        movs    r1, #0
        str     r1, [sp, #24]           @ ... and force bio_xfer to read
        ldr     r1, [sp, #12]
        lsrs    r1, r1, #1              @ containing page
        movs    r2, #1
        adr     r3, bio_scratch
        bl      bio_xfer
        ldr     r1, [sp, #0]
        str     r1, [sp, #24]           @ restore before any exit path
        cmp     r0, #0
        bne     .Lbio_pfail
        @ r3 = the half of the page this LBA maps to, r2 = the caller's buffer.
        adr     r3, bio_scratch
        ldr     r0, [sp, #12]
        movs    r1, #1
        ands    r0, r1
        lsls    r0, r0, #12             @ 0 or 4096
        adds    r3, r3, r0
        ldr     r2, [sp, #16]
        ldr     r0, [sp, #0]
        cmp     r0, #0
        beq     .Lbio_copy_go           @ read: scratch half -> caller
        movs    r0, r2                  @ write: caller -> scratch half
        movs    r2, r3
        movs    r3, r0
.Lbio_copy_go:
        movs    r6, #1
        lsls    r6, r6, #12
.Lbio_copy:
        ldr     r0, [r3, #0]
        str     r0, [r2, #0]
        adds    r3, #4
        adds    r2, #4
        subs    r6, #4
        bne     .Lbio_copy
        @ Write leg: push the patched page back. [sp,#24] is already 1 here, so
        @ bio_xfer picks the write op.
        ldr     r0, [sp, #0]
        cmp     r0, #0
        beq     .Lbio_partial_adv
        ldr     r1, [sp, #12]
        lsrs    r1, r1, #1
        movs    r2, #1
        adr     r3, bio_scratch
        bl      bio_xfer
        cmp     r0, #0
        bne     .Lbio_pfail
.Lbio_partial_adv:
        ldr     r0, [sp, #20]
        subs    r0, #1
        str     r0, [sp, #20]
        ldr     r0, [sp, #12]
        adds    r0, #1
        str     r0, [sp, #12]
        ldr     r0, [sp, #16]
        movs    r1, #1
        lsls    r1, r1, #12
        adds    r0, r0, r1
        str     r0, [sp, #16]
        b       .Lbio_loop

@ bio_xfer - one FTL transfer of r2 whole pages starting at page r1, to/from
@ buffer r3. Mirrors the stock tail, including the FlushDataCache call and its
@ skip for a negative buffer address. Returns r0 = 0 on success. Preserves
@ r5/r7; clobbers r0-r3.
        .type   bio_xfer, %function
        .align  2
bio_xfer:
        push    {r4, r6, lr}
        sub     sp, #16
        movs    r4, r1                  @ startPage
        movs    r6, r2                  @ nPages
        str     r3, [sp, #12]           @ buffer
        cmp     r3, #0
        blt     .Lbio_xfer_go
        lsls    r2, r6, #13             @ Length = nPages * 8192
        str     r2, [sp, #0]
        movs    r2, #0
        str     r2, [sp, #4]            @ Length hi
        str     r2, [sp, #8]            @ FlushType
        ldr     r0, [r5, #8]            @ EFI_CPU_ARCH_PROTOCOL
        ldr     r1, [r0, #0]            @ ->FlushDataCache
        ldr     r2, [sp, #12]           @ Start lo
        movs    r3, #0                  @ Start hi
        blx     r1
.Lbio_xfer_go:
        @ +52 = the caller's +24 (isWrite): 12 pushed here + 16 frame here + 24.
        ldr     r0, [sp, #52]
        cmp     r0, #0
        bne     .Lbio_xfer_write
        movs    r0, r7
        movs    r1, r4
        movs    r2, r6
        ldr     r3, [sp, #12]
        bl      NAND_ARGS_READ
        movs    r1, r0
        movs    r0, #NAND_OP_READ
        b       .Lbio_xfer_switch
.Lbio_xfer_write:
        movs    r0, r7
        movs    r1, r4
        movs    r2, r6
        ldr     r3, [sp, #12]
        bl      NAND_ARGS_WRITE
        movs    r1, r0
        movs    r0, #NAND_OP_WRITE
.Lbio_xfer_switch:
        bl      NAND_SWITCH
        add     sp, #16
        pop     {r4, r6, pc}

        .ltorg

@ bio_scratch - the one-page bounce buffer. 32-byte aligned because it is a DMA
@ destination, and it must stay within Thumb-1 `adr` range (PC+1020) of the two
@ references above, i.e. immediately after this code.
        .align  5
        .global bio_scratch
bio_scratch:
        .space  8192
