package nand16gb

import (
	"fmt"
	"os"

	"github.com/freemyipod/wInd3x/pkg/uasm"
)

// Like AUPD (patch_aupd.go), RetailOS carries the same NAND driver disk mode
// runs, just in a different spot, so it gets the same fixes from the same
// assembly sources with unique offsets.
//
// Unlike the other layers, OSOS has two address spaces:
//
//	FLASH 0x00000000..0x00a4a56f  the image as stored == byte offsets into the
//	                              slice callers hand us. Every constant below
//	                              is a FLASH offset.
//	SRAM  0x22000000..            FLASH 0x0..0xf8dc, copied there at boot.
//	DRAM  0x08000000..            FLASH 0xf8dc.., copied there at boot. This is
//	                              where the NAND driver actually RUNS.
//
// Patch bytes at FLASH offsets, but every absolute address baked into the
// trampolines must be the DRAM address - ososVA() converts.
//
// The storage executors compute `ratio = 4096 / pageSize`, which an 8 KiB page
// makes 0, so every LBA and count is multiplied by zero. osos_blockbridge.S
// supplies the real translation.

const (
	// ososFlashDRAMSplit is the FLASH offset at which the DRAM image starts;
	// everything below it is the SRAM image (0x22000000), which is exactly
	// 0xf8dc long.
	ososFlashDRAMSplit = 0xf8dc
	ososDRAMBase       = 0x08000000
	ososImageSize      = 0xa4a570

	// Two-plane erase: each FIL erase's reset, plus the literal-pool slots the
	// trampoline reloads FMC/globals/descriptor from.
	ososEraseSeqHook    = 0x002d3a0c
	ososEraseSeqBack    = 0x002d3a14
	ososSeqGandLit      = 0x002d3a44
	ososSeqFmcLit       = 0x002d3a4c
	ososSeqDescLit      = 0x002d3a50
	ososEraseSingleHook = 0x002d3b00
	ososEraseSingleBack = 0x002d3b08
	ososSglFmcLit       = 0x002d3b3c
	ososSglDescLit      = 0x002d3b44

	ososNandReset = 0x000e4394
	ososWaitCS    = 0x000a2590

	// Erased-page poison scrub: entry detour of the function that checks ECC,
	// resuming at entry+4 (the trampoline re-issues the displaced `stmdb`).
	ososRxECCSite   = 0x000cdfac
	ososRxECCResume = 0x000cdfb0

	// GC tombstone suppression: the `mov r0,#0x55` stamp and the `strb` after it.
	ososGcStamp    = 0x000e4170
	ososGcStampNop = 0x000e4174

	// Both-planes bad-block scan type 4's case and its three stock exits.
	ososBBTScanHook = 0x0008d200
	ososBBTScanErr  = 0x0008d140
	ososBBTScanBad  = 0x0008d310
	ososBBTScanGood = 0x0008d398

	// The readback-verify memcmp inside the special metadata block writer.
	ososVerifyMemcmp = 0x0009d114

	// NAND heap sizing - the OSOS counterpart of disk mode's heap patches.
	// One region is allocated and then carved up:
	//
	//	base + 0x000 .. 0x200      header
	//	base + 0x200 .. 0x7d200    the WMR arena   (0x7d000 = 512,000 bytes)
	//	base + 0x7d200 .. 0x7de00  six 0x200-byte scratch buffers
	//
	// A region smaller than 0x80000 is rejected outright, and the allocators
	// bump-allocate inside the arena and fail closed against the baked 0x7d000
	// limit. Successful pointers are OR-ed with 0x80000000, the uncached alias.
	//
	// ososHeapAllocSite does two jobs: it is the recorded region size, and an
	// `orr r0,r1,r1,asr #0xd` downstream derives the allocation size from it.
	// Raising the constant scales both.
	ososHeapAllocSite   = 0x000f4a20 // mov r1,#0x80000  - size + the allocation
	ososHeapInitSite    = 0x000f4a9c // mov r1,#0x80000  - size passed to NAND Init
	ososHeapSegmentSite = 0x0036d3ac // add r0,r0,#0x7d000 - scratch past the arena
	ososHeapCmpSiteA    = 0x0004e364 // cmp r0,#0x7d000
	ososHeapCmpSiteB    = 0x0004e3d0 // cmp r1,#0x7d000
	ososHeapCmpSiteC    = 0x0004e420 // cmp r0,#0x7d000

	// The stock values being replaced.
	ososHeapStockRegion = 0x80000
	ososHeapStockArena  = 0x7d000

	// Sized to the measured demand. OSOS shares one allocator between the NAND
	// region and the UI, fonts included, so over-reserving starves the text
	// path and can corrupt the vector table; see the bitmap guards below. The
	// high-water mark after a
	// full FTL mount measured 0x1257a0, and 0x180000 keeps ~30% headroom while
	// still clearing FTL init's 1 MiB single allocation.
	ososHeapFullSize  = 0x200000
	ososHeapArenaSize = 0x180000

	// The stock 4 KiB logical block size, as a literal. It also appears where
	// the code means "one block is one page", so it cannot simply be raised;
	// the bridge translates instead.
	ososStockSectorSize = 0x1000

	// 4K<->8K storage bridge (osos_blockbridge.S). The hooks go on the
	// `mov r0,#0x1000` that starts the ratio computation, not on the `mul` two
	// instructions later, so the stock page-size literal is overwritten and the
	// divide never runs rather than being computed and discarded. r4/r5/r6
	// (lba/count/buf) are already live at this point.
	ososExecReadHook  = 0x002c1304 // read executor, dispatches vt[+0xc]
	ososExecReadRet   = 0x002c132c // ldmia sp!,{r3,r4,r5,r6,r7,pc}
	ososExecWriteHook = 0x002c135c // write executor, dispatches vt[+0x10]
	ososExecWriteRet  = 0x002c1384
	// Both executors load the storage object from the same globals pair; these
	// are the two PC-relative literals holding its DRAM address, taken from the
	// image at patch time rather than hardcoded. [pair+0]=vtable, [pair+4]=obj.
	ososBlockPairLit  = 0x002c1330
	ososBlockPairLit2 = 0x002c1388
	// The cache-line walk that pairs with the 0x80000000 uncached-alias
	// convention (it early-returns when bit 31 is already set).
	ososCacheClean = 0x00033224 // clean a range, 32 bytes at a time
	ososAllocDMA   = 0x000e08f8 // DMA buffer allocator (size, kind)

	// Bitmap allocation guard: the constructor never checks the allocation
	// before memset-clearing it, so an exhausted pool turns the clear into
	// memset(0, 0, 8192) over the exception vector table.
	ososBitmapAllocCall = 0x0027d7a0
	ososBitmapAllocWord = 0xebf98c54 // the stock `bl` to the DMA allocator

	// Bitmap store guard: the alloc guard above only covers the constructor's
	// clear; the set-bit accessor dereferences bitmap->data with no check, so
	// an exhausted pool can still corrupt the vector table one bit at a time.
	// Both arms converge on one store, so one hook covers it.
	ososBitmapStoreSite = 0x0027d6b8
	ososBitmapStoreWord = 0xe7801105 // str r1,[r0,r5,lsl #2], the stock encoding

	// The bridge's static 8 KiB read-modify-write page: reserved, not
	// allocated (see osos_blockbridge.S's get_scratch). It sits in a
	// 0x2371-byte zero run, the only one of that size with no word anywhere in
	// the image pointing into it. 0x2020 = the page plus 0x20 of alignment
	// slack for get_scratch.
	ososScratchOff  = 0x00743060
	ososScratchSize = 0x2020

	// The capacity expression, `*out = pageCount / (0x1000 / pageSize)`, which
	// divides by zero here. ososLBACalcStart is the `mov r0,r5` that begins the
	// ratio computation; ososLBACountLdr is the `ldr r0,[sp,#8]` that fetches
	// the page count, relocated to the front.
	ososLBACalcStart = 0x002c10fc
	ososLBACountLdr  = 0x002c1108

	// Stock encodings verified before anything is overwritten. The epilogue is
	// worth checking explicitly: the trampolines jump here and let it pop the
	// real return address, so a wrong target returns to garbage with no clue.
	ososExecEpilogueWord = 0xe8bd80f8 // ldmia sp!,{r3,r4,r5,r6,r7,pc}
	ososMovR0R5Word      = 0xe1a00005 // mov r0,r5      (ososLBACalcStart)
	ososLdrR0SP8Word     = 0xe59d0008 // ldr r0,[sp,#8] (ososLBACountLdr)
	ososAddR0R0R0Word    = 0xe0800000 // add r0,r0,r0   - the *2 we write
	ososDRAMRegionHigh   = 0x0a000000

	// device-table entry the 16GB chip descriptor is injected over
	retailOSChipDescOffset = 0x9269BC

	// where the trampoline blobs go: a 0xe76-byte zero run, the only one of its
	// size in the code/rodata region with no word anywhere in the image
	// pointing into it. It sits between two string tables, i.e. inter-section
	// padding rather than a zero-initialised variable. splice() still verifies
	// every byte it overwrites is zero.
	ososPatchOff    = 0x3cbf78
	ososPatchOffEnd = 0x3ccdec
)

// converts a FLASH offset (what every constant here uses) to the DRAM address
// the code runs at
func ososVA(flashOff uint32) uint32 {
	return ososDRAMBase + flashOff - ososFlashDRAMSplit
}

// the inverse of ososVA, for imageSplicer
func ososOff(va uint32) int {
	return int(va - ososDRAMBase + ososFlashDRAMSplit)
}

// writes an ARM branch at FLASH offset hookOff targeting DRAM address
// targetVA; the branch is computed in DRAM space, where both ends run
func ososPutBranch(osos []byte, hookOff uint32, targetVA uint32, link bool) {
	enc := armB
	if link {
		enc = armBL
	}
	putWord(osos, int(hookOff), enc(ososVA(hookOff), targetVA))
}

// rewrites the reported capacity: stock `*out = pageCount / (0x1000/pageSize)`
// divides by zero here, and with the logical block staying at 4096 one 8 KiB
// page is two logical blocks, so the fix is `*out = pageCount * 2`.
func applyRetailOSLBACount4K(osos []byte) error {
	if got := getWord(osos, ososLBACalcStart); got != ososMovR0R5Word {
		return fmt.Errorf("osos LBA count: 0x%x is 0x%08x, want the stock `mov r0,r5` 0x%08x",
			ososLBACalcStart, got, uint32(ososMovR0R5Word))
	}
	pageCountLdr := getWord(osos, ososLBACountLdr)
	if pageCountLdr != ososLdrR0SP8Word {
		return fmt.Errorf("osos LBA count: 0x%x is 0x%08x, want the stock `ldr r0,[sp,#8]` 0x%08x",
			ososLBACountLdr, pageCountLdr, uint32(ososLdrR0SP8Word))
	}
	nop := asmWord(armNop)
	putWord(osos, ososLBACalcStart+0x0, pageCountLdr)      // ldr r0,[sp,#8]
	putWord(osos, ososLBACalcStart+0x4, ososAddR0R0R0Word) // add r0,r0,r0
	putWord(osos, ososLBACalcStart+0x8, nop)
	putWord(osos, ososLBACalcStart+0xc, nop)
	putWord(osos, ososLBACalcStart+0x10, nop)
	return nil
}

// ApplyRetailOSPatches applies the 16GB NAND patchset to RetailOS's own NAND
// driver, mutating osos in place. osos starts at the OSOS image's own base;
// that image has no IMG1 header, so slice offset == FLASH offset.
func ApplyRetailOSPatches(osos []byte) error {
	if len(osos) < ososImageSize {
		return fmt.Errorf("osos too short: %d < %d", len(osos), ososImageSize)
	}
	if err := applyRetailOSChipDescriptor(osos); err != nil {
		return err
	}
	if err := applyRetailOSLBACount4K(osos); err != nil {
		return err
	}
	if err := applyRetailOSHeapSizeFix(osos); err != nil {
		return err
	}
	return applyRetailOSNANDFixes(osos)
}

// widens the WMR NAND arena so this chip's larger FTL structures fit.
//
// The arena is 0x7d000 (512,000 bytes); FTL init asks for 8192*128 = 1 MiB,
// twice the whole arena. The allocator fails closed, the FTL never mounts, the
// storage device is never attached, and the first I/O dispatches through a NULL
// vtable into the panic handler, which resets the SoC.
func applyRetailOSHeapSizeFix(osos []byte) error {
	for _, site := range []struct {
		name string
		off  int
		from uasm.Statement
		to   uasm.Statement
	}{
		{"region size + allocation", ososHeapAllocSite,
			uasm.Mov{Dest: uasm.R1, Src: uasm.Immediate(ososHeapStockRegion)},
			uasm.Mov{Dest: uasm.R1, Src: uasm.Immediate(ososHeapFullSize)}},
		{"size passed to NAND Init", ososHeapInitSite,
			uasm.Mov{Dest: uasm.R1, Src: uasm.Immediate(ososHeapStockRegion)},
			uasm.Mov{Dest: uasm.R1, Src: uasm.Immediate(ososHeapFullSize)}},
		{"arena segmentation", ososHeapSegmentSite,
			uasm.Add{Dest: uasm.R0, Src: uasm.R0, Compl: uasm.Immediate(ososHeapStockArena)},
			uasm.Add{Dest: uasm.R0, Src: uasm.R0, Compl: uasm.Immediate(ososHeapArenaSize)}},
		{"arena limit A", ososHeapCmpSiteA,
			uasm.Cmp{A: uasm.R0, B: uasm.Immediate(ososHeapStockArena)},
			uasm.Cmp{A: uasm.R0, B: uasm.Immediate(ososHeapArenaSize)}},
		{"arena limit B", ososHeapCmpSiteB,
			uasm.Cmp{A: uasm.R1, B: uasm.Immediate(ososHeapStockArena)},
			uasm.Cmp{A: uasm.R1, B: uasm.Immediate(ososHeapArenaSize)}},
		{"arena limit C", ososHeapCmpSiteC,
			uasm.Cmp{A: uasm.R0, B: uasm.Immediate(ososHeapStockArena)},
			uasm.Cmp{A: uasm.R0, B: uasm.Immediate(ososHeapArenaSize)}},
	} {
		// The three cmp sites are in near-identical sibling allocators, so
		// check the stock encoding before overwriting it.
		if got, want := getWord(osos, site.off), asmWord(site.from); got != want {
			return fmt.Errorf("osos heap %s: 0x%x is 0x%08x, want the stock 0x%08x",
				site.name, site.off, got, want)
		}
		putWord(osos, site.off, asmWord(site.to))
	}
	return nil
}

// injects the 16GB chip definition into RetailOS's device table
func applyRetailOSChipDescriptor(osos []byte) error {
	copy(osos[retailOSChipDescOffset:], ChipDescriptor)
	return nil
}

// splices the trampolines and installs their hooks, mirroring
// applyAUPDNANDFixes patch for patch
func applyRetailOSNANDFixes(osos []byte) error {
	workDir, err := os.MkdirTemp("", "nand16gb-osos-patch-*")
	if err != nil {
		return fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	s := &imageSplicer{
		layer: "osos", img: osos, workDir: workDir,
		next: ososVA(ososPatchOff), end: ososVA(ososPatchOffEnd), off: ososOff,
	}

	// --- two-plane erase (nand_planeerase.S) ---
	syms, err := s.splice("nand_planeerase.S", defsyms{}.
		Hex("NAND_RESET", ososVA(ososNandReset)).
		Hex("WAIT_CS", ososVA(ososWaitCS)).
		Hex("SEQ_FMC_LIT", ososVA(ososSeqFmcLit)).
		Hex("SEQ_GAND_LIT", ososVA(ososSeqGandLit)).
		Hex("SEQ_DESC_LIT", ososVA(ososSeqDescLit)).
		Hex("SEQ_BACK", ososVA(ososEraseSeqBack)).
		Hex("SGL_FMC_LIT", ososVA(ososSglFmcLit)).
		Hex("SGL_DESC_LIT", ososVA(ososSglDescLit)).
		Hex("SGL_BACK", ososVA(ososEraseSingleBack)))
	if err != nil {
		return err
	}
	eraseSeq, err := mustSym(syms, "nand_planeerase.S", "tramp_eraseseq_p1")
	if err != nil {
		return err
	}
	eraseSingle, err := mustSym(syms, "nand_planeerase.S", "tramp_erasesingle_p1")
	if err != nil {
		return err
	}
	ososPutBranch(osos, ososEraseSeqHook, eraseSeq, false)
	ososPutBranch(osos, ososEraseSingleHook, eraseSingle, false)

	// --- erased-page poison scrub + GC tombstone suppression (nand_erasedpage.S) ---
	syms, err = s.splice("nand_erasedpage.S", defsyms{}.Hex("ECC_RESUME", ososVA(ososRxECCResume)))
	if err != nil {
		return err
	}
	gcFix, err := mustSym(syms, "nand_erasedpage.S", "gc_erased_check")
	if err != nil {
		return err
	}
	ososPutBranch(osos, ososGcStamp, gcFix, true)
	putWord(osos, ososGcStampNop, asmWord(armNop))

	chunkFix, err := mustSym(syms, "nand_erasedpage.S", "erased_chunk_fix")
	if err != nil {
		return err
	}
	ososPutBranch(osos, ososRxECCSite, chunkFix, false)

	// --- factory bad-block scan that sees both planes (nand_bbtscan.S) ---
	bsDefsyms := defsyms{}.
		Hex("RDERR", ososVA(ososBBTScanErr)).
		Hex("BAD", ososVA(ososBBTScanBad)).
		Hex("GOOD", ososVA(ososBBTScanGood))
	syms, err = s.splice("nand_bbtscan.S", bsDefsyms)
	if err != nil {
		return err
	}
	tramp, err := mustSym(syms, "nand_bbtscan.S", "tramp_bbt4")
	if err != nil {
		return err
	}
	ososPutBranch(osos, ososBBTScanHook, tramp, false)

	// --- 4K logical over 8K pages (osos_blockbridge.S) ---
	//
	// The globals pair holding the storage object comes from the image's own
	// literal pool rather than being hardcoded. Both executors load the same
	// address, so disagreement means the offsets have drifted.
	pair := getWord(osos, ososBlockPairLit)
	if pair2 := getWord(osos, ososBlockPairLit2); pair != pair2 {
		return fmt.Errorf("osos block bridge: the two storage-object literals disagree "+
			"(0x%x=0x%08x, 0x%x=0x%08x); the executor offsets have drifted",
			ososBlockPairLit, pair, ososBlockPairLit2, pair2)
	}
	if pair < ososDRAMBase || pair >= ososDRAMRegionHigh {
		return fmt.Errorf("osos block bridge: storage-object literal 0x%08x is not a DRAM address", pair)
	}
	for _, site := range []struct {
		name string
		hook int
		ret  int
	}{
		{"read executor", ososExecReadHook, ososExecReadRet},
		{"write executor", ososExecWriteHook, ososExecWriteRet},
	} {
		wantHook := asmWord(uasm.Mov{Dest: uasm.R0, Src: uasm.Immediate(ososStockSectorSize)})
		if got := getWord(osos, site.hook); got != wantHook {
			return fmt.Errorf("osos %s hook: 0x%x is 0x%08x, want the stock `mov r0,#0x1000` 0x%08x",
				site.name, site.hook, got, wantHook)
		}
		if got := getWord(osos, site.ret); got != ososExecEpilogueWord {
			return fmt.Errorf("osos %s return target: 0x%x is 0x%08x, want the epilogue "+
				"`ldmia sp!,{r3,r4,r5,r6,r7,pc}` 0x%08x; the trampoline returns by "+
				"jumping here, so this must be the real epilogue",
				site.name, site.ret, got, uint32(ososExecEpilogueWord))
		}
	}
	// The static scratch page must be untouched image padding, the same check
	// imageSplicer makes for the trampoline region and for the same reason.
	for i := 0; i < ososScratchSize; i++ {
		if osos[ososScratchOff+i] != 0 {
			return fmt.Errorf("osos block bridge: scratch reservation at FLASH 0x%x is not free "+
				"(byte 0x%x at +0x%x); pick another gap",
				ososScratchOff, osos[ososScratchOff+i], i)
		}
	}
	syms, err = s.splice("osos_blockbridge.S", defsyms{}.
		Hex("OSOS_BLK_PAIR", pair).
		Hex("OSOS_SCRATCH", ososVA(ososScratchOff)).
		Hex("OSOS_CACHE_CLEAN", ososVA(ososCacheClean)).
		Hex("OSOS_ALLOC_DMA", ososVA(ososAllocDMA)).
		Hex("OSOS_RD_RET", ososVA(ososExecReadRet)).
		Hex("OSOS_WR_RET", ososVA(ososExecWriteRet)))
	if err != nil {
		return err
	}
	rd, err := mustSym(syms, "osos_blockbridge.S", "tramp_osos_read")
	if err != nil {
		return err
	}
	wr, err := mustSym(syms, "osos_blockbridge.S", "tramp_osos_write")
	if err != nil {
		return err
	}
	ososPutBranch(osos, ososExecReadHook, rd, false)
	ososPutBranch(osos, ososExecWriteHook, wr, false)

	// Bitmap allocation guard: redirect the constructor's alloc call so a
	// failed allocation zeroes nbits too, and the unconditional clear that
	// follows writes 0 bytes instead of 8192 over the exception vectors.
	if got := getWord(osos, ososBitmapAllocCall); got != ososBitmapAllocWord {
		return fmt.Errorf("osos bitmap alloc guard: 0x%x is 0x%08x, want the stock "+
			"call to the DMA allocator 0x%08x",
			ososBitmapAllocCall, got, uint32(ososBitmapAllocWord))
	}
	allocGuard, err := mustSym(syms, "osos_blockbridge.S", "tramp_bitmap_alloc")
	if err != nil {
		return err
	}
	ososPutBranch(osos, ososBitmapAllocCall, allocGuard, true)

	// Bitmap store guard: with only the alloc guard above, the set-bit accessor
	// can still write through a null bitmap into the exception vectors.
	if got := getWord(osos, ososBitmapStoreSite); got != ososBitmapStoreWord {
		return fmt.Errorf("osos bitmap store guard: 0x%x is 0x%08x, want the stock "+
			"`str r1,[r0,r5,lsl #2]` 0x%08x",
			ososBitmapStoreSite, got, uint32(ososBitmapStoreWord))
	}
	storeGuard, err := mustSym(syms, "osos_blockbridge.S", "tramp_bitmap_store")
	if err != nil {
		return err
	}
	ososPutBranch(osos, ososBitmapStoreSite, storeGuard, false) // B: we never come back

	// --- special block write readback-verify always passes ---
	putWord(osos, ososVerifyMemcmp, asmWord(uasm.Mov{Dest: uasm.R0, Src: uasm.Immediate(0)}))

	return nil
}
