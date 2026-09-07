@ nand_erasedpage.S - the two erased-page fixes for the Whimory (WMR) NAND
@ driver, shared by disk mode, AUPD and RetailOS with per-layer addresses.
@
@   erased_chunk_fix  - an erased 8K page reads back as ECC poison with an
@                       uncorrectable verdict. Scrub it to 0xFF and synthesize
@                       the blank verdict callers expect.
@   gc_erased_check   - don't let GC tombstone a page that only failed to read
@                       because it is blank.
@
@ ECC_RESUME is the one absolute address left in the file, required with no
@ fallback value. It points just past the displaced entry `stmdb` of the ECC
@ check being detoured. Every layer otherwise assembles identical bytes.
        .syntax unified
        .arm
        .text

@ erased_chunk_fix: detours the entry of the ECC check, replacing its
@   `stmdb sp!,{r4,r5,r6,lr}` prologue. It repairs the per-2KB-chunk read
@   buffer so every consumer downstream - normal reads, RMW splices, GC
@   relocation, refresh, bad-block scan, context scan - sees data instead of
@   poison.
@
@   An erased 8K page reports aggregate ECC status 0x40000000 (uncorrectable,
@   0 bit-errors); the hardware never sets the 0x20000000 blank bit at 8K.
@   Per-chunk statuses live at FMC[0xd24] (advanced +4/group; base = ptr -
@   4*FMC[0xd28]) with matching per-chunk DMA dest addresses at FMC[0xd20]. An
@   erased chunk's dest buffer holds poison, not 0xFF.
@
@   Detection is by data pattern, not status: the per-chunk status array lies
@   on this silicon, since an erased chunk holding poison can still report
@   status 0. An erased 8K chunk instead reads back a fixed pattern, identical
@   across erased chunks, beginning 0x88a0a0a0,0x200a02a0 - the ECC core's
@   mangled decode of all-0xFF. Any chunk matching that 2-word signature gets
@   its 2KB dest set to 0xFF, which can only turn poison into 0xFF and never
@   corrupt real data (odds of a real chunk's first 8 bytes matching are about
@   1 in 1.8e19).
@
@   Scrubbing the data alone isn't enough, because consumers still see the
@   uncorrectable verdict. The check returns 0x80020000 (uncorrectable),
@   1 (blank) or 0 (good); we synthesize blank conservatively:
@     gate: only act on aggregate uncorrectable + 0 bit-errors, anything else
@       leaves the stock path untouched.
@     per chunk: word0==0xFFFFFFFF -> already blank; poison -> scrub to 0xFF;
@       else -> real/undetected (counted in r10).
@     real_count == 0          -> all erased -> return 1 (blank). Returning 0
@                                 would run the context scan past its end and
@                                 report a nonsense capacity.
@     0 < real_count < groups  -> partial -> return 0 (good).
@     real_count == groups     -> nothing detected erased -> stock, so the
@                                 context scan never regresses.
@   Reported capacity must stay around 15GB; a much larger one means the blank
@   verdict has leaked into the context scan and the gate is too loose.
@
@   Live at entry: r0 = aggregate ECC status (FMC[0xc30]), r1 = err-count out
@   ptr, r2 = count, lr = caller. r4-r11 are callee-saved, so we preserve
@   r4-r10; r3/r12 are scratch.
        .global erased_chunk_fix
        .type   erased_chunk_fix, %function
        .equ    POISON_W0, 0x88a0a0a0    @ erased-chunk ECC-garbage signature word 0
        .equ    POISON_W1, 0x200a02a0    @ ... word 1
erased_chunk_fix:
        stmfd   sp!, {r4-r10}            @ preserve callee-saved scratch (incl r10=real_count)
        ldr     r8, =0x38a00000          @ FMC base
        ldr     r9, [r8, #0xd28]         @ group count (chunks; 4 per 8K page)
        cmp     r9, #0
        beq     .ecf_orig                @ no groups -> stock path
        cmp     r9, #64
        bhi     .ecf_orig                @ sanity clamp -> stock path
        tst     r0, #0x40000000          @ aggregate uncorrectable? (erased candidate)
        beq     .ecf_orig                @ no -> normal read -> stock
        tst     r0, #0xff                @ any bit-errors? -> real bad data
        bne     .ecf_orig                @ -> stock (never mask real corruption)
        ldr     r5, [r8, #0xd20]
        sub     r5, r5, r9, lsl #2       @ r5 = per-chunk dest-addr array base
        ldr     r6, =POISON_W0
        ldr     r7, =POISON_W1
        mov     r4, #0                   @ chunk index
        mov     r10, #0                  @ real_count (real / undetected chunks)
.ecf_loop:
        cmp     r4, r9
        bhs     .ecf_verdict
        ldr     r12, [r5, r4, lsl #2]    @ dest addr of chunk i
        orr     r12, r12, #0x80000000    @ uncached alias (true DMA buffer)
        ldr     r3, [r12]                @ word0
        cmn     r3, #1                   @ word0 == 0xFFFFFFFF (already blank)?
        beq     .ecf_next                @ erased -> not real, no scrub
        cmp     r3, r6
        bne     .ecf_real                @ not poison -> real / undetected
        ldr     r3, [r12, #4]            @ word1
        cmp     r3, r7
        bne     .ecf_real                @ not poison -> real / undetected
        @ poison chunk -> scrub its 2KB to 0xFF
        mvn     r3, #0                   @ 0xFFFFFFFF
        add     r8, r12, #0x800          @ end ptr (r8 free now; reloaded next entry)
.ecf_fill:
        str     r3, [r12], #4
        cmp     r12, r8
        blo     .ecf_fill
        b       .ecf_next
.ecf_real:
        add     r10, r10, #1             @ a real / undetected chunk
.ecf_next:
        add     r4, r4, #1
        b       .ecf_loop
.ecf_verdict:
        cmp     r10, #0
        beq     .ecf_blank               @ all chunks erased -> BLANK
        cmp     r10, r9
        beq     .ecf_orig                @ none detected erased -> stock
        mov     r0, #0                   @ partial page -> GOOD (deliver real chunks)
        cmp     r1, #0
        strne   r0, [r1]                 @ zero the err count
        ldmfd   sp!, {r4-r10}
        bx      lr                       @ return 0
.ecf_blank:
        mov     r0, #0
        cmp     r1, #0
        strne   r0, [r1]                 @ zero the err count
        mov     r0, #1                   @ blank verdict
        ldmfd   sp!, {r4-r10}
        bx      lr                       @ return 1
.ecf_orig:
        ldmfd   sp!, {r4-r10}            @ restore entry state (r0/r1/r2/lr untouched)
        stmdb   sp!, {r4, r5, r6, lr}    @ the replaced prologue instruction
        b       ECC_RESUME               @ -> back into the function body

@ gc_erased_check: the GC-local half of the same problem. Detours the 0x55 stamp
@ in the GC/reclaim pass; the `strb r0,[r9,#0xa]` after it is NOP'd by the
@ patcher. GC stamps 0x55 when a relocation read fails, but an erased page reads
@ uncorrectable only because it is blank, so recompute that page's read buffer
@ (r4*pageSize + *(r11+0x10)) and skip the stamp if it is all-0xFF.
@
@ Live: r4 = page-in-block index, r9 = spare record, r10 = driver globals
@ (pageSize at +0x34), r11 = buffer base at +0x10. r9/r10/r11 preserved. The ECC
@ check itself is left alone, so the FTL context scan still sees erased reads
@ fail and capacity stays correct.
@
@ The eviction merge has a structurally identical 0x55 stamp that is not hooked
@ here. Never observed to bite, but it is the first place to look if the
@ firmware volume goes unreadable on a device with stable power.
        .global gc_erased_check
        .type   gc_erased_check, %function
gc_erased_check:
        ldrh    r1, [r10, #0x34]         @ pageSize
        mul     r0, r4, r1               @ r4 * pageSize  (rd,rm,rs all distinct)
        ldr     r1, [r11, #0x10]         @ buffer base
        add     r0, r0, r1               @ this page's read buffer
        orr     r0, r0, #0x80000000      @ uncached alias (true DMA bytes)
        mov     r2, #0x800               @ scan the first 2 KiB
        mvn     r3, #0                   @ 0xFFFFFFFF
1:      ldr     r12, [r0], #4
        cmp     r12, r3
        bne     .gc_real                 @ a non-FF word -> real data -> stamp
        subs    r2, r2, #4
        bne     1b
        bx      lr                       @ all-FF = erased -> skip the stamp
.gc_real:
        mov     r0, #0x55                @ the replaced instruction (real bad page)
        strb    r0, [r9, #0xa]
        bx      lr
