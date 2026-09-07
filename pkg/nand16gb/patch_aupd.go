package nand16gb

import (
	"fmt"
	"os"

	"github.com/freemyipod/wInd3x/pkg/uasm"
)

// AUPD carries the same NAND driver as disk mode, just at different
// addresses, so this mirrors patch_diskmode.go hook for hook and reuses the
// same assembly sources.

const (
	// AUPD is loaded contiguously at 0x08000000; the slice callers pass starts
	// at the IMG1 header, hence the 0x800.
	aupdVABase     = 0x08000000
	aupdIMG1Header = 0x800
	aupdBodySize   = 0x12b194 // IMG1 header's declared body length

	// Two-plane erase: each FIL erase's reset, plus the literal-pool
	// slots the trampoline reloads FMC/globals/descriptor from.
	aupdEraseSeqHook    = 0x08014f0c
	aupdEraseSeqBack    = 0x08014f14
	aupdSeqGandLit      = 0x08014f44
	aupdSeqFmcLit       = 0x08014f4c
	aupdSeqDescLit      = 0x08014f50
	aupdEraseSingleHook = 0x08015000
	aupdEraseSingleBack = 0x08015008
	aupdSglFmcLit       = 0x0801503c
	aupdSglDescLit      = 0x08015044

	aupdNandReset = 0x08010c40
	aupdWaitCS    = 0x08010c60

	// Erased-page poison scrub: entry detour of the function that checks ECC,
	// resuming at entry+4 (the trampoline re-issues the displaced `stmdb`).
	aupdRxECCSite   = 0x0800ff00
	aupdRxECCResume = 0x0800ff04

	// GC tombstone suppression: the `mov r0,#0x55` stamp and the `strb` after it.
	aupdGcStamp    = 0x0800df3c
	aupdGcStampNop = 0x0800df40

	// Both-planes bad-block scan type 4's case and its three stock exits.
	aupdBBTScanHook = 0x08009934
	aupdBBTScanErr  = 0x08009874
	aupdBBTScanBad  = 0x08009a44
	aupdBBTScanGood = 0x08009acc

	// The readback-verify memcmp inside the special metadata block writer.
	aupdVerifyMemcmp = 0x0800fb74

	// device-table entry the 16GB chip descriptor is injected over
	aupdChipDescVA = 0x0801bb84

	// where the trampoline blobs are spliced: a 0x85a-byte zero run in the
	// picture-resource area, unreferenced anywhere in the image, so the worst
	// case is pixels. splice() verifies every byte it overwrites is zero.
	aupdPatchVA    = 0x0802af80
	aupdPatchVAEnd = 0x0802b7d8
)

// converts an AUPD firmware VA to a byte offset in the IMG1-header-relative
// slice callers pass ApplyAUPDPatches
func aupdVAToOff(va uint32) int {
	return aupdIMG1Header + int(va-aupdVABase)
}

func aupdPutWord(aupd []byte, va, word uint32) {
	putWord(aupd, aupdVAToOff(va), word)
}

// ApplyAUPDPatches applies the 16GB NAND patchset to AUPD's own NAND driver,
// mutating aupd in place. aupd starts at the AUPD IMG1 header
func ApplyAUPDPatches(aupd []byte) error {
	if err := applyAUPDChipDescriptor(aupd); err != nil {
		return err
	}
	return applyAUPDNANDFixes(aupd)
}

// injects the 16GB chip definition into AUPD's device table
func applyAUPDChipDescriptor(aupd []byte) error {
	off := aupdVAToOff(aupdChipDescVA)
	if need := off + len(ChipDescriptor); len(aupd) < need {
		return fmt.Errorf("aupd too short for chip descriptor: %d < %d", len(aupd), need)
	}
	copy(aupd[off:], ChipDescriptor)
	return nil
}

// splices the trampolines and installs their hooks
func applyAUPDNANDFixes(aupd []byte) error {
	if len(aupd) < aupdIMG1Header+aupdBodySize {
		return fmt.Errorf("aupd too short for NAND patches: %d < %d", len(aupd), aupdIMG1Header+aupdBodySize)
	}

	workDir, err := os.MkdirTemp("", "nand16gb-aupd-patch-*")
	if err != nil {
		return fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	s := &imageSplicer{
		layer: "aupd", img: aupd, workDir: workDir,
		next: aupdPatchVA, end: aupdPatchVAEnd, off: aupdVAToOff,
	}

	// --- two-plane erase (nand_planeerase.S) ---
	syms, err := s.splice("nand_planeerase.S", defsyms{}.
		Hex("NAND_RESET", uint32(aupdNandReset)).
		Hex("WAIT_CS", uint32(aupdWaitCS)).
		Hex("SEQ_FMC_LIT", uint32(aupdSeqFmcLit)).
		Hex("SEQ_GAND_LIT", uint32(aupdSeqGandLit)).
		Hex("SEQ_DESC_LIT", uint32(aupdSeqDescLit)).
		Hex("SEQ_BACK", uint32(aupdEraseSeqBack)).
		Hex("SGL_FMC_LIT", uint32(aupdSglFmcLit)).
		Hex("SGL_DESC_LIT", uint32(aupdSglDescLit)).
		Hex("SGL_BACK", uint32(aupdEraseSingleBack)))
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
	aupdPutWord(aupd, aupdEraseSeqHook, armB(aupdEraseSeqHook, eraseSeq))
	aupdPutWord(aupd, aupdEraseSingleHook, armB(aupdEraseSingleHook, eraseSingle))

	// --- erased-page poison scrub + GC tombstone suppression (nand_erasedpage.S) ---
	syms, err = s.splice("nand_erasedpage.S", defsyms{}.Hex("ECC_RESUME", uint32(aupdRxECCResume)))
	if err != nil {
		return err
	}
	gcFix, err := mustSym(syms, "nand_erasedpage.S", "gc_erased_check")
	if err != nil {
		return err
	}
	aupdPutWord(aupd, aupdGcStamp, armBL(aupdGcStamp, gcFix))
	aupdPutWord(aupd, aupdGcStampNop, asmWord(armNop))

	chunkFix, err := mustSym(syms, "nand_erasedpage.S", "erased_chunk_fix")
	if err != nil {
		return err
	}
	aupdPutWord(aupd, aupdRxECCSite, armB(aupdRxECCSite, chunkFix))

	// --- factory bad-block scan that sees both planes (nand_bbtscan.S) ---
	bsDefsyms := defsyms{}.
		Hex("RDERR", uint32(aupdBBTScanErr)).
		Hex("BAD", uint32(aupdBBTScanBad)).
		Hex("GOOD", uint32(aupdBBTScanGood))
	syms, err = s.splice("nand_bbtscan.S", bsDefsyms)
	if err != nil {
		return err
	}
	tramp, err := mustSym(syms, "nand_bbtscan.S", "tramp_bbt4")
	if err != nil {
		return err
	}
	aupdPutWord(aupd, aupdBBTScanHook, armB(aupdBBTScanHook, tramp))

	// --- special block write readback-verify always passes ---
	//
	// The verify memcmp fails on this chip's 8K pages, leaving a format that
	// passes presence checks but will not mount. Same fix as disk mode's.
	aupdPutWord(aupd, aupdVerifyMemcmp, asmWord(uasm.Mov{Dest: uasm.R0, Src: uasm.Immediate(0)}))

	return nil
}
