package nand16gb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

// N3G EFI NAND driver (PE32, GUID 945F3B55-95A5-4BD9-AEED-6EC243B813A8)
//
// efiNandModuleBase is this PE32's fixed link base
const efiNandModuleBase = 0x40250000

// Hook site RVAs
const (
	// sequential erase
	efiEraseSeqLoopHook = 0x6c96
	efiEraseSeqBulkHook = 0x6cbe

	// single erase
	efiEraseSingleHook = 0x6d44

	efiBBTScanHook = 0x56d6
)

// The efi_nand.S symbols the hook sites above branch into; see that file for
// what each does.
const (
	efiTrampErase     = "tramp_efi_erase_p1"
	efiTrampBBTScan   = "tramp_efi_bbt_scan"
	efiTrampBlockIO4K = "tramp_efi_blockio_4k"
)

// Block IO entry points, whose bodies are replaced wholesale rather than
// hooked, by applyEFIBlockIO4K.
const (
	efiReadBlocksRVA  = 0x224
	efiWriteBlocksRVA = 0x28a

	// Both functions open with an identical 10-byte prologue and argument
	// load, then a 16-byte stretch computing the broken page/count. The stub
	// goes over that 16-byte stretch, starting 10 bytes in.
	efiBlockIOStubOff = 0xa
	efiBlockIOStubLen = 0x10
	// Byte offset of the `bl` within the stub blockIOStub emits.
	efiBlockIOStubBLOff = 8
)

// efiBlockIOStockPrefix is the first 12 bytes of the replaced stretch, the
// same in ReadBlocks and WriteBlocks:
//
//	movs r7,#0 ; ldr r4,[sp,#0x44] ; ldr r2,[r5,#0x0]
//	movs r0,r6 ; movs r1,r7        ; add r3,sp,#0x10
//
// The remaining 4 bytes are a `blx` to the 64-bit divide helper, whose
// PC-relative encoding differs between the two sites, so it is checked by
// shape rather than by value.
var efiBlockIOStockPrefix = []byte{
	0x00, 0x27, 0x11, 0x9c, 0x2a, 0x68,
	0x30, 0x00, 0x39, 0x00, 0x04, 0xab,
}

// blockIOStub builds the replacement body. It keeps the stock PC-relative
// literal loads so nothing depends on where the module actually loads, which is
// not efiNandModuleBase.
//
//	ldr  r7,[pc,#..]      @ NAND op arg block (literal at RVA 0x40c)
//	ldr  r4,[sp,#0x44]    @ Buffer
//	ldr  r2,[sp,#0x20]    @ LBA (spilled by the stock prologue's push)
//	movs r3,#isWrite
//	bl   tramp_efi_blockio_4k
//	add  sp,#0x2c
//	pop  {r4,r5,r6,r7,pc}
func blockIOStub(ldrR7 uint16, isWrite byte) []byte {
	return []byte{
		byte(ldrR7), byte(ldrR7 >> 8),
		0x11, 0x9c, // ldr r4,[sp,#0x44]
		0x08, 0x9a, // ldr r2,[sp,#0x20]
		isWrite, 0x23, // movs r3,#isWrite
		0, 0, 0, 0, // bl, filled in by putThumbBL
		0x0b, 0xb0, // add sp,#0x2c
		0xf0, 0xbd, // pop {r4,r5,r6,r7,pc}
	}
}

// thumbNop: Thumb-1 nop.
const thumbNop = 0x46c0

func putThumbNop(data []byte, off int) {
	binary.LittleEndian.PutUint16(data[off:off+2], thumbNop)
}

// thumbBL encodes a Thumb-1 `bl dst` placed at srcVA, calling into dst with no
// instruction-set switch since both sides are Thumb. The ARM equivalents are
// patch_diskmode.go's armB/armBL.
func thumbBL(srcVA, dstVA uint32) [4]byte {
	off := uint32(int32(dstVA) - int32(srcVA+4))
	high := uint16(0xf000 | ((off >> 12) & 0x7ff))
	low := uint16(0xf800 | ((off >> 1) & 0x7ff))
	var b [4]byte
	binary.LittleEndian.PutUint16(b[0:2], high)
	binary.LittleEndian.PutUint16(b[2:4], low)
	return b
}

func putThumbBL(data []byte, off int, srcVA, dstVA uint32) {
	b := thumbBL(srcVA, dstVA)
	copy(data[off:off+4], b[:])
}

// replaceThumbCall rewrites the 4-byte Thumb `bl` at hookRVA to call target,
// then NOPs out the rest of displacedBytes, which must cover whole 4-byte BLs.
// A stranded second halfword has bits[15:11] = 0b11111, so the decoder reads it
// as the start of a new 32-bit instruction and swallows what follows.
func replaceThumbCall(out []byte, hookRVA int, srcVA, target uint32, displacedBytes int) error {
	if displacedBytes < 4 || displacedBytes%2 != 0 {
		return fmt.Errorf("hook 0x%x: displacedBytes %d must be even and >= 4",
			hookRVA, displacedBytes)
	}
	if hookRVA+displacedBytes > len(out) {
		return fmt.Errorf("hook 0x%x: displaces %d bytes past the end of the blob",
			hookRVA, displacedBytes)
	}
	putThumbBL(out, hookRVA, srcVA, target)
	for off := 4; off < displacedBytes; off += 2 {
		putThumbNop(out, hookRVA+off)
	}
	return nil
}

// peLastSectionOffsets locates the PE32 header fields ApplyEFINANDPatches
// rewrites when growing the image: the file offset of SizeOfImage, and of the
// last section's VirtualSize/SizeOfRawData. Requires and verifies the flat
// RVA == file offset == VA layout this PE32 relies on.
func peLastSectionOffsets(pe32 []byte) (sizeOfImageOff, lastSectionOff int, err error) {
	if len(pe32) < 0x40 || pe32[0] != 'M' || pe32[1] != 'Z' {
		return 0, 0, fmt.Errorf("not a PE image (no MZ signature)")
	}
	peOff := int(binary.LittleEndian.Uint32(pe32[0x3c:0x40]))
	if peOff < 0 || peOff+24 > len(pe32) || string(pe32[peOff:peOff+4]) != "PE\x00\x00" {
		return 0, 0, fmt.Errorf("bad PE signature")
	}
	nsec := int(binary.LittleEndian.Uint16(pe32[peOff+6 : peOff+8]))
	opthdrsize := int(binary.LittleEndian.Uint16(pe32[peOff+20 : peOff+22]))
	optOff := peOff + 24
	if nsec == 0 || optOff+96 > len(pe32) {
		return 0, 0, fmt.Errorf("no sections or optional header truncated")
	}
	sizeOfImageOff = optOff + 56
	sizeOfImage := binary.LittleEndian.Uint32(pe32[sizeOfImageOff : sizeOfImageOff+4])

	secTableOff := optOff + opthdrsize
	lastSectionOff = secTableOff + (nsec-1)*40
	if lastSectionOff+40 > len(pe32) {
		return 0, 0, fmt.Errorf("section table truncated")
	}
	vsize := binary.LittleEndian.Uint32(pe32[lastSectionOff+8 : lastSectionOff+12])
	vaddr := binary.LittleEndian.Uint32(pe32[lastSectionOff+12 : lastSectionOff+16])
	rawsize := binary.LittleEndian.Uint32(pe32[lastSectionOff+16 : lastSectionOff+20])
	rawptr := binary.LittleEndian.Uint32(pe32[lastSectionOff+20 : lastSectionOff+24])

	if uint32(len(pe32)) != sizeOfImage {
		return 0, 0, fmt.Errorf("file length %d != SizeOfImage 0x%x - not a flat RVA==offset layout", len(pe32), sizeOfImage)
	}
	if vaddr != rawptr || vsize != rawsize || vaddr+vsize != sizeOfImage {
		return 0, 0, fmt.Errorf("last section isn't flat/trailing (vaddr=0x%x vsize=0x%x rawptr=0x%x rawsize=0x%x sizeOfImage=0x%x)", vaddr, vsize, rawptr, rawsize, sizeOfImage)
	}
	return sizeOfImageOff, lastSectionOff, nil
}

// growPE32 appends code past the image and widens SizeOfImage and the last
// section's VirtualSize/SizeOfRawData so the EFI PE loader maps the new bytes.
func growPE32(pe32 []byte, code []byte) ([]byte, error) {
	sizeOfImageOff, lastSectionOff, err := peLastSectionOffsets(pe32)
	if err != nil {
		return nil, fmt.Errorf("growPE32: %w", err)
	}
	grow := uint32(len(code))
	out := append([]byte{}, pe32...)

	newVsize := binary.LittleEndian.Uint32(out[lastSectionOff+8:lastSectionOff+12]) + grow
	binary.LittleEndian.PutUint32(out[lastSectionOff+8:lastSectionOff+12], newVsize)
	binary.LittleEndian.PutUint32(out[lastSectionOff+16:lastSectionOff+20], newVsize)

	newSizeOfImage := binary.LittleEndian.Uint32(out[sizeOfImageOff:sizeOfImageOff+4]) + grow
	binary.LittleEndian.PutUint32(out[sizeOfImageOff:sizeOfImageOff+4], newSizeOfImage)

	return append(out, code...), nil
}

// efiNandArgsLiteralRVA is the module-relative address of the literal holding
// the pointer to the NAND op argument block. Both Block IO functions load it
// PC-relatively; the stub loads it up front so the trampoline gets it in a
// register.
const efiNandArgsLiteralRVA = 0x40c

// thumbLDRLiteral encodes `ldr rD,[pc,#imm]` reaching litRVA from an
// instruction at siteRVA. Thumb's literal base is (PC+4) rounded down to a word
// and the offset is scaled by 4; wrong by 4 bytes here loads the neighbouring
// literal and reads the NAND through a garbage pointer.
func thumbLDRLiteral(rD int, siteRVA, litRVA int) (uint16, error) {
	base := (siteRVA + 4) &^ 3
	delta := litRVA - base
	if delta < 0 || delta%4 != 0 || delta/4 > 0xff {
		return 0, fmt.Errorf("ldr r%d at 0x%x cannot reach literal 0x%x (delta %d)",
			rD, siteRVA, litRVA, delta)
	}
	return uint16(0x4800 | (rD << 8) | (delta / 4)), nil
}

// applyEFIBlockIO4K replaces the bodies of the NAND Block IO ReadBlocks and
// WriteBlocks with stubs that call tramp_efi_blockio_4k, which serves the
// 4096-byte block out of this chip's 8192-byte pages. The 4 KiB block itself
// stays: it is the addressing contract disk mode writes the firmware volume
// against (sector 63 = byte 0x3F000).
func applyEFIBlockIO4K(out []byte, trampVA uint32) error {
	for _, site := range []struct {
		name    string
		rva     int
		isWrite byte
	}{
		{"ReadBlocks", efiReadBlocksRVA, 0},
		{"WriteBlocks", efiWriteBlocksRVA, 1},
	} {
		off := site.rva + efiBlockIOStubOff
		if off+efiBlockIOStubLen > len(out) {
			return fmt.Errorf("%s stub at 0x%x runs past the end of the module", site.name, off)
		}
		got := out[off : off+efiBlockIOStubLen]
		if !bytes.Equal(got[:len(efiBlockIOStockPrefix)], efiBlockIOStockPrefix) {
			return fmt.Errorf("%s at 0x%x: expected % x, found % x",
				site.name, off, efiBlockIOStockPrefix, got[:len(efiBlockIOStockPrefix)])
		}
		// The tail of the replaced stretch must be the 32-bit `blx` to the
		// divide helper (first halfword 0xF0xx); anything else means the
		// offsets have drifted.
		if got[13]&0xf8 != 0xf0 {
			return fmt.Errorf("%s at 0x%x: expected a 32-bit branch at +0xc, found % x",
				site.name, off, got[12:16])
		}

		ldrR7, err := thumbLDRLiteral(7, off, efiNandArgsLiteralRVA)
		if err != nil {
			return fmt.Errorf("%s: %w", site.name, err)
		}
		copy(got, blockIOStub(ldrR7, site.isWrite))
		putThumbBL(out, off+efiBlockIOStubBLOff,
			efiNandModuleBase+uint32(off)+efiBlockIOStubBLOff, trampVA)
	}
	return nil
}

// ApplyEFINANDPatches ports the two-plane erase and both-planes bad-block-scan
// fixes, and replaces the Block IO read/write bodies with 4 KiB-over-8 KiB
// stubs (see efi_nand.S), in the N3G EFI NAND driver's PE32 module. pe32 is
// that module's raw PE32 section content; the returned slice is longer, since
// the trampolines are appended past the end of the image, and its PE header is
// updated to match.
func ApplyEFINANDPatches(pe32 []byte) ([]byte, error) {
	trampolineVA := efiNandModuleBase + uint32(len(pe32))

	workDir, err := os.MkdirTemp("", "nand16gb-efi-patch-*")
	if err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	code, syms, err := assembleLinkARM(workDir, "efi_nand.S", trampolineVA, nil)
	if err != nil {
		return nil, fmt.Errorf("assemble efi_nand.S: %w", err)
	}

	out, err := growPE32(pe32, code)
	if err != nil {
		return nil, err
	}

	eraseVA, err := mustSym(syms, "efi_nand.S", efiTrampErase)
	if err != nil {
		return nil, err
	}
	eraseVA &^= 1
	for _, hookRVA := range []int{efiEraseSeqLoopHook, efiEraseSeqBulkHook, efiEraseSingleHook} {
		srcVA := efiNandModuleBase + uint32(hookRVA)
		if err := replaceThumbCall(out, hookRVA, srcVA, eraseVA, 8); err != nil {
			return nil, err
		}
	}

	bioVA, err := mustSym(syms, "efi_nand.S", efiTrampBlockIO4K)
	if err != nil {
		return nil, err
	}
	bioVA &^= 1
	if err := applyEFIBlockIO4K(out, bioVA); err != nil {
		return nil, err
	}

	// Factory bad-block scan that sees both planes. Independent of the erase
	// fix above, and it has to be here rather than only in disk mode: on a
	// normal boot it is the EFI that initializes the NAND first and builds the
	// bad block table.
	scanVA, err := mustSym(syms, "efi_nand.S", efiTrampBBTScan)
	if err != nil {
		return nil, err
	}
	scanVA &^= 1
	srcVA := efiNandModuleBase + uint32(efiBBTScanHook)
	if err := replaceThumbCall(out, efiBBTScanHook, srcVA, scanVA, 4); err != nil {
		return nil, err
	}

	return out, nil
}

// ThumbLDRLiteralForTest exposes thumbLDRLiteral to pkg/cfw's tests, which pin
// the encodings baked into the Block IO stub expectations.
func ThumbLDRLiteralForTest(rD, siteRVA, litRVA int) (uint16, error) {
	return thumbLDRLiteral(rD, siteRVA, litRVA)
}
