package nand16gb

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/freemyipod/wInd3x/pkg/uasm"
)

// DiskModeBlobSize is the exact length of the stock diskflsh blob these patch addresses assume.
const DiskModeBlobSize = 280512 // 0x447C0

const (
	diskmodeDramVABase   = 0x08000000
	diskmodeDramFileBase = 0x51f8

	// verified-free zero gap the bridge trampoline (diskmode_scsibridge.S) is spliced into
	diskmodePatchVA   = 0x080385d0
	diskmodeReadHook  = 0x0802252c
	diskmodeWriteHook = 0x080221d0

	diskmodeGetBlockSize = 0x0802ae54
	diskmodeGetLBACount  = 0x080224f4
	diskmodeCalcDivSite  = 0x0802ea30 // the divide-by-zero in the page-parameter calc

	// the force-under-length checks in the SCSI read/write executors
	diskmodeForceUnderRead  = 0x0801abf4
	diskmodeForceUnderWrite = 0x0801b2d8
)

const (
	// gap for the scratch-RMW FTL bridge, and the two FTL read/write
	// conversion sites it hooks
	diskmodeFtlBridgeVA      = 0x08038b80
	diskmodeFtlBridgeVACeil  = 0x08039a00 // the erased-page blob starts here
	diskmodeFtlReadConvSite  = 0x0802ec3c
	diskmodeFtlWriteConvSite = 0x0802ec94

	// the readback-verify memcmp inside the special metadata block writer
	diskmodeVerifyMemcmp = 0x080146a8

	// Erased-page poison scrub + GC tombstone suppression (both from nand_erasedpage.S).
	diskmodeErasedPageVA    = 0x08039a00
	diskmodeErasedPageVAEnd = 0x0803a26c
	diskmodeGcStamp         = 0x08019fc0 // the `mov r0,#0x55` stamp
	diskmodeGcStampNop      = 0x08019fc4 // the `strb` after it -> NOP
	diskmodeRxECCSite       = 0x08017808 // entry `stmdb` of the ECC check (detour)
	diskmodeRxECCResume     = diskmodeRxECCSite + 4

	// Two-plane erase (nand_planeerase.S)
	diskmodePlaneEraseVA     = 0x08039680 // free gap below the erased-page blob, gap end 0x08039908
	diskmodePlaneEraseGapEnd = 0x08039908
	// each FIL erase's reset, plus the literal-pool slots the trampoline
	// reloads FMC/globals/descriptor from
	diskmodeEraseSeqHook    = 0x08032608
	diskmodeEraseSingleHook = 0x080326fc
	diskmodeNandReset       = 0x0801a1e4
	diskmodeWaitCS          = 0x080151f8
	diskmodeSeqFmcLit       = 0x08032648
	diskmodeSeqGandLit      = 0x08032640
	diskmodeSeqDescLit      = 0x0803264c
	diskmodeEraseSeqBack    = 0x08032610
	diskmodeSglFmcLit       = 0x08032738
	diskmodeSglDescLit      = 0x08032740
	diskmodeEraseSingleBack = 0x08032704

	// device table bake
	diskmodeDeviceTableLiteral = 0x08032458
	diskmodeDeviceEntrySize    = 0x2c
	diskmodeChipIndex          = 15

	// capacity reserve in 8K pages: 0x8000 pages = 256 MiB (CAP_RESERVE in diskmode_scsibridge.S)
	diskmodeCapReserve = 0x8000
)

// wordPatch is one VA -> raw little-endian ARM words patch.
type wordPatch struct {
	va    uint32
	words []uint32
}

// `mov r0, r0` - the standard ARM no-op encoding
var armNop = uasm.Mov{Dest: uasm.R0, Src: uasm.R0}

var diskmodeWordPatches = []wordPatch{
	{
		// return 0x1000 (4 KiB) instead of the raw 0x2000 page size
		va: diskmodeGetBlockSize,
		words: []uint32{
			asmWord(uasm.Mov{Dest: uasm.R0, Src: uasm.Immediate(0x1000)}),
			asmWord(uasm.Bx{Dest: uasm.LR}),
		},
	},
	{
		// replace the divide-by-zero pair with *out = total_pages << 1
		va: diskmodeCalcDivSite,
		words: []uint32{
			asmWord(uasm.Ldr{Dest: uasm.R0, Src: uasm.Deref(uasm.SP, 8)}), // total_pages
			0xe1a00080, // lsl r0, r0, #1 - uasm has no shifted-register operand
			asmWord(uasm.Str{Src: uasm.R0, Dest: uasm.Deref(uasm.R4, 0)}), // *out
			asmWord(armNop),
			asmWord(armNop),
			asmWord(armNop),
			asmWord(armNop),
		},
	},
	{
		va:    diskmodeForceUnderRead,
		words: []uint32{asmWord(armNop)},
	},
	{
		va:    diskmodeForceUnderWrite,
		words: []uint32{asmWord(armNop)},
	},
}

// Bigger NAND means a bigger FTL context: enlarge the heap.
const (
	diskmodeHeapFullSize = 0x400000
	diskmodeHeapSize     = 0x380000

	diskmodeHeapAllocSite1  = 0x2416c // the full allocation is performed here
	diskmodeHeapAllocSite2  = 0x241e8 // 0x80000 passed through to NAND Init, actually use the full allocation
	diskmodeHeapSegmentSite = 0x3b1e0 // segments the heap into different sizes, expand the biggest one
	diskmodeHeapCmpSiteA    = 0xefb4  // malloc compare against the new segment size
	diskmodeHeapCmpSiteB    = 0xef64  // malloc compare against the new segment size
	diskmodeHeapCmpSiteC    = 0xeef8  // third cmp against the new segment size, in the heap stats dump
)

// heapPatch is one blob-offset -> ARM instruction patch.
type heapPatch struct {
	offset int
	insn   uasm.Statement
}

// reissues each site with the new heap sizes baked in
var diskmodeHeapPatches = []heapPatch{
	{diskmodeHeapAllocSite1, uasm.Mov{Dest: uasm.R1, Src: uasm.Immediate(diskmodeHeapFullSize)}},
	{diskmodeHeapAllocSite2, uasm.Mov{Dest: uasm.R1, Src: uasm.Immediate(diskmodeHeapFullSize)}},
	{diskmodeHeapSegmentSite, uasm.Add{Dest: uasm.R0, Src: uasm.R0, Compl: uasm.Immediate(diskmodeHeapSize)}},
	{diskmodeHeapCmpSiteA, uasm.Cmp{A: uasm.R0, B: uasm.Immediate(diskmodeHeapSize)}},
	{diskmodeHeapCmpSiteB, uasm.Cmp{A: uasm.R1, B: uasm.Immediate(diskmodeHeapSize)}},
	{diskmodeHeapCmpSiteC, uasm.Cmp{A: uasm.R0, B: uasm.Immediate(diskmodeHeapSize)}},
}

func assembleOne(insn uasm.Statement) []byte {
	program := uasm.Program{Address: 0, Listing: []uasm.Statement{insn}}
	return program.Assemble()
}

// assembleOne, as a little-endian word
func asmWord(insn uasm.Statement) uint32 {
	return binary.LittleEndian.Uint32(assembleOne(insn))
}

// converts a firmware VA to a byte offset in the disk-mode blob, which loads
// file[0..0x51f8) into IRAM and file[0x51f8..] into DRAM at 0x08000000
func vaToOff(va uint32) int {
	return diskmodeDramFileBase + int(va-diskmodeDramVABase)
}

func armB(srcVA, dstVA uint32) uint32 {
	off := int32(dstVA) - int32(srcVA+8)
	if off&3 != 0 {
		panic("branch target not word aligned")
	}
	imm24 := uint32(off>>2) & 0xFFFFFF
	return 0xEA000000 | imm24
}

func armBL(srcVA, dstVA uint32) uint32 {
	off := int32(dstVA) - int32(srcVA+8)
	if off&3 != 0 {
		panic("branch target not word aligned")
	}
	imm24 := uint32(off>>2) & 0xFFFFFF
	return 0xEB000000 | imm24
}

func putWord(data []byte, off int, w uint32) {
	binary.LittleEndian.PutUint32(data[off:off+4], w)
}

func getWord(data []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(data[off : off+4])
}

func putBranchWord(data []byte, srcVA uint32, word uint32) {
	off := vaToOff(srcVA)
	putWord(data, off, word)
}

func mustSym(syms symtab, srcFile, name string) (uint32, error) {
	addr, ok := syms[name]
	if !ok {
		return 0, fmt.Errorf("%s: symbol %s not found", srcFile, name)
	}
	return addr, nil
}

// ApplyDiskModePatches applies the full 16GB-NAND disk-mode patchset,
// mutating diskflsh in place.
func ApplyDiskModePatches(diskflsh []byte) error {
	if len(diskflsh) < DiskModeBlobSize {
		return fmt.Errorf("diskflsh too short: %d < %d", len(diskflsh), DiskModeBlobSize)
	}

	workDir, err := os.MkdirTemp("", "nand16gb-patch-*")
	if err != nil {
		return fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	// 1. bridge trampoline: device table + capacity-from-geometry + reserve
	trampDefsyms := defsyms{}.Int("CAP_RESERVE", diskmodeCapReserve)
	trampCode, trampSyms, err := assembleLinkARM(workDir, "diskmode_scsibridge.S", diskmodePatchVA, trampDefsyms)
	if err != nil {
		return fmt.Errorf("assemble diskmode_scsibridge.S: %w", err)
	}
	trOff := vaToOff(diskmodePatchVA)
	if trOff+len(trampCode) > len(diskflsh) {
		return fmt.Errorf("trampoline overruns blob (%d bytes @ 0x%x)", len(trampCode), diskmodePatchVA)
	}
	copy(diskflsh[trOff:trOff+len(trampCode)], trampCode)

	tlc, err := mustSym(trampSyms, "diskmode_scsibridge.S", "tramp_lba_count")
	if err != nil {
		return err
	}
	putBranchWord(diskflsh, diskmodeGetLBACount, armB(diskmodeGetLBACount, tlc))

	// 2. raw word patches
	for _, wp := range diskmodeWordPatches {
		base := vaToOff(wp.va)
		for i, w := range wp.words {
			putWord(diskflsh, base+i*4, w)
		}
	}

	// 3. bake the 16GB chip descriptor over the template device-table entry, the same blob every other layer injects
	tableVA := getWord(diskflsh, vaToOff(diskmodeDeviceTableLiteral))
	if !(tableVA >= diskmodeDramVABase && tableVA < diskmodeDramVABase+0x40000) {
		return fmt.Errorf("device table VA 0x%08x out of range", tableVA)
	}
	chip := vaToOff(tableVA + diskmodeChipIndex*diskmodeDeviceEntrySize)
	copy(diskflsh[chip:chip+diskmodeDeviceEntrySize], ChipDescriptor)

	// 4. erased-page poison scrub + GC tombstone suppression: one blob, two hooks
	erasedDefsyms := defsyms{}.Hex("ECC_RESUME", diskmodeRxECCResume)
	erasedCode, erasedSyms, err := assembleLinkARM(workDir, "nand_erasedpage.S", diskmodeErasedPageVA, erasedDefsyms)
	if err != nil {
		return fmt.Errorf("assemble nand_erasedpage.S: %w", err)
	}
	if diskmodeErasedPageVA+uint32(len(erasedCode)) > diskmodeErasedPageVAEnd {
		return fmt.Errorf("nand_erasedpage.S (%d bytes) overruns the zero run @0x%x (ends 0x%x)", len(erasedCode), diskmodeErasedPageVA, diskmodeErasedPageVAEnd)
	}
	dOff := vaToOff(diskmodeErasedPageVA)
	copy(diskflsh[dOff:dOff+len(erasedCode)], erasedCode)

	gcFix, err := mustSym(erasedSyms, "nand_erasedpage.S", "gc_erased_check")
	if err != nil {
		return err
	}
	putBranchWord(diskflsh, diskmodeGcStamp, armBL(diskmodeGcStamp, gcFix))
	putBranchWord(diskflsh, diskmodeGcStampNop, asmWord(armNop))

	chunkFix, err := mustSym(erasedSyms, "nand_erasedpage.S", "erased_chunk_fix")
	if err != nil {
		return err
	}
	putBranchWord(diskflsh, diskmodeRxECCSite, armB(diskmodeRxECCSite, chunkFix))

	// 5. special-block write readback-verify always passes
	putBranchWord(diskflsh, diskmodeVerifyMemcmp, asmWord(uasm.Mov{Dest: uasm.R0, Src: uasm.Immediate(0)}))

	// 6. scratch-RMW 4K<->8K fix on the FTL read/write path
	ftlCode, ftlSyms, err := assembleLinkARM(workDir, "diskmode_ftlbridge.S", diskmodeFtlBridgeVA, nil)
	if err != nil {
		return fmt.Errorf("assemble diskmode_ftlbridge.S: %w", err)
	}
	if diskmodeFtlBridgeVA < diskmodePatchVA+uint32(len(trampCode)) {
		return fmt.Errorf("FTL bridge VA 0x%x overlaps the SCSI bridge (ends 0x%x)", diskmodeFtlBridgeVA, diskmodePatchVA+uint32(len(trampCode)))
	}
	if diskmodeFtlBridgeVA+uint32(len(ftlCode)) > diskmodeFtlBridgeVACeil {
		return fmt.Errorf("FTL bridge (%d B) ends 0x%x, past the erased-page blob at 0x%x", len(ftlCode), diskmodeFtlBridgeVA+uint32(len(ftlCode)), diskmodeFtlBridgeVACeil)
	}
	pOff := vaToOff(diskmodeFtlBridgeVA)
	copy(diskflsh[pOff:pOff+len(ftlCode)], ftlCode)

	ftlRd, err := mustSym(ftlSyms, "diskmode_ftlbridge.S", "tramp_ftl_rd")
	if err != nil {
		return err
	}
	ftlWr, err := mustSym(ftlSyms, "diskmode_ftlbridge.S", "tramp_ftl_wr")
	if err != nil {
		return err
	}
	putBranchWord(diskflsh, diskmodeFtlReadConvSite, armB(diskmodeFtlReadConvSite, ftlRd))
	putBranchWord(diskflsh, diskmodeFtlWriteConvSite, armB(diskmodeFtlWriteConvSite, ftlWr))

	// 7. two-plane erase, spliced last so its free-region check sees the FTL bridge blob already written
	peDefsyms := defsyms{}.
		Hex("NAND_RESET", diskmodeNandReset).
		Hex("WAIT_CS", diskmodeWaitCS).
		Hex("SEQ_FMC_LIT", diskmodeSeqFmcLit).
		Hex("SEQ_GAND_LIT", diskmodeSeqGandLit).
		Hex("SEQ_DESC_LIT", diskmodeSeqDescLit).
		Hex("SEQ_BACK", diskmodeEraseSeqBack).
		Hex("SGL_FMC_LIT", diskmodeSglFmcLit).
		Hex("SGL_DESC_LIT", diskmodeSglDescLit).
		Hex("SGL_BACK", diskmodeEraseSingleBack)
	peCode, peSyms, err := assembleLinkARM(workDir, "nand_planeerase.S", diskmodePlaneEraseVA, peDefsyms)
	if err != nil {
		return fmt.Errorf("assemble nand_planeerase.S: %w", err)
	}
	if diskmodePlaneEraseVA+uint32(len(peCode)) > diskmodePlaneEraseGapEnd {
		return fmt.Errorf("two-plane erase: blob %d bytes overruns the gap end 0x%x", len(peCode), diskmodePlaneEraseGapEnd)
	}
	peOff := vaToOff(diskmodePlaneEraseVA)
	for _, b := range diskflsh[peOff : peOff+len(peCode)] {
		if b != 0 {
			return fmt.Errorf("two-plane erase: target 0x%x not free (overlaps another patch); free a gap", diskmodePlaneEraseVA)
		}
	}
	copy(diskflsh[peOff:peOff+len(peCode)], peCode)

	eraseSeq, err := mustSym(peSyms, "nand_planeerase.S", "tramp_eraseseq_p1")
	if err != nil {
		return err
	}
	eraseSingle, err := mustSym(peSyms, "nand_planeerase.S", "tramp_erasesingle_p1")
	if err != nil {
		return err
	}
	putBranchWord(diskflsh, diskmodeEraseSeqHook, armB(diskmodeEraseSeqHook, eraseSeq))
	putBranchWord(diskflsh, diskmodeEraseSingleHook, armB(diskmodeEraseSingleHook, eraseSingle))

	// 8. grow the heap allocation sites to fit this chip's FTL/VFL context and page buffers (blob file offsets, not VAs)
	for _, p := range diskmodeHeapPatches {
		copy(diskflsh[p.offset:], assembleOne(p.insn))
	}

	return nil
}
