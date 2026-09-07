package cfw

import (
	"fmt"

	"github.com/freemyipod/wInd3x/pkg/devices"
	"github.com/freemyipod/wInd3x/pkg/efi"
	"github.com/freemyipod/wInd3x/pkg/image"
	"github.com/freemyipod/wInd3x/pkg/nand16gb"
)

// IMG1 headers are 0x800 bytes long
const n3gIMG1HeaderSize = 0x800

// the NAND driver module, patched by three of the visitors below
const n3gEFINANDGUID = "945F3B55-95A5-4BD9-AEED-6EC243B813A8"

// disables signature checking in the ROM validator EFI module
func n3gROMValidatorVisitor() *VisitPE32InFile {
	return &VisitPE32InFile{
		FileGUID: efi.MustParseGUID("773641A1-CC51-41B7-B121-943BD7C5FC3F"),
		Patch: Patches([]Patch{
			PatchAt{Address: 0x7ee, To: []byte{0x00, 0x20, 0x00, 0x00}},
			PatchAt{Address: 0x7f6, To: []byte{0x00, 0x20, 0x70, 0x47}},
			PatchAt{Address: 0x85c, To: []byte{0x00, 0x20, 0x00, 0x00}},
			PatchAt{Address: 0x830, To: []byte{0x14, 0x25}},
			PatchAt{Address: 0x864, To: []byte{0x00, 0x20}},
		}),
	}
}

// patches the 16GB NAND chip definition into the N3G NAND driver EFI module
func n3gNewNANDVisitor() *VisitPE32InFile {
	return &VisitPE32InFile{
		FileGUID: efi.MustParseGUID(n3gEFINANDGUID),
		Patch: Patches([]Patch{
			PatchAt{
				Address: 0x8400,
				To:      nand16gb.ChipDescriptor,
			},
		}),
	}
}

// fixes the LBA-count math for an 8192-byte page under a 4096-byte Block IO
// block. Stock derives Ratio = BlockSize / gPageSize ("pages per block"),
// which is 0 here, then divides the page count by it. Swapping the divide's
// operands makes Ratio "blocks per page" (2) and the dependent divide becomes
// a multiply, so the media reports pageCount * 2 blocks. The 4096-byte block
// stays - it is the addressing contract disk mode writes the firmware volume
// against. See tramp_efi_blockio_4k.
func n3gEFINANDGeometryVisitor() *VisitPE32InFile {
	return &VisitPE32InFile{
		FileGUID: efi.MustParseGUID(n3gEFINANDGUID),
		Patch: Patches([]Patch{
			// swap the udiv operands: r0 = gPageSize, r1 = BlockSize
			PatchAtExpect{
				Address: 0x3a2,
				From:    []byte{0x29, 0x68, 0x38, 0x00}, // ldr r1,[r5,#0]; movs r0,r7
				To:      []byte{0x28, 0x68, 0x39, 0x00}, // ldr r0,[r5,#0]; movs r1,r7
			},
			// store Ratio, then multiply the page count by it instead of
			// dividing. The trailing 4 bytes are the second `blx udiv`
			PatchAtExpect{
				Address: 0x3aa,
				From: []byte{
					0x01, 0x00, // movs r1,r0
					0x68, 0x60, // str  r0,[r5,#0x4]
					0x04, 0x98, // ldr  r0,[sp,#0x10]
					0x07, 0xf0, 0xf4, 0xea, // blx udiv
				},
				To: []byte{
					0x68, 0x60, // str  r0,[r5,#0x4]
					0x04, 0x99, // ldr  r1,[sp,#0x10]
					0x48, 0x43, // muls r0,r1
					0xc0, 0x46, // nop
					0xc0, 0x46, // nop
				},
			},
		}),
	}
}

// ports the two-plane erase/ECC fix into the EFI NAND driver
func n3gNANDPlaneEraseECCVisitor() *VisitPE32InFile {
	return &VisitPE32InFile{
		FileGUID: efi.MustParseGUID(n3gEFINANDGUID),
		Patch: ApplyFunc(func(in []byte) ([]byte, error) {
			return nand16gb.ApplyEFINANDPatches(in)
		}),
	}
}

// doubles the firmware volume from 64 MiB to 128 MiB so a ~90 MB firmware
// image fits: the LastBlock computation multiplies an 8 KiB NAND page count by
// a 4 KiB logical block, undercounting by half - the usual 4K/8K identity break
func n3gEFIFirmwareRegionVisitor() *VisitPE32InFile {
	return &VisitPE32InFile{
		FileGUID: efi.MustParseGUID("43B93232-AFBE-11D4-BD0F-0080C73C8881"),
		Patch: Patches([]Patch{
			PatchAtExpect{
				Address: 0x64c,
				From:    []byte{0x71, 0x41}, // adcs r1,r6
				To:      []byte{0x40, 0x00}, // lsls r0,r0,#1
			},
			// drop the child Block IO's own start/end bound checks in the FS
			// Read/Write functions, so neither rejects requests past the
			// pre-16GB range
			PatchAtExpect{
				Address: 0x526,
				From:    []byte{0x02, 0xd2}, // bcs 0x52e
				To:      []byte{0x02, 0xe0}, // b   0x52e
			},
			PatchAtExpect{
				Address: 0x586,
				From:    []byte{0x02, 0xd2}, // bcs 0x58e
				To:      []byte{0x02, 0xe0}, // b   0x58e
			},
		}),
	}
}

// the patchset shared by the Recovery and Firmware EFI volumes
func n3gEFIVisitors() []VolumeVisitor {
	return []VolumeVisitor{
		n3gROMValidatorVisitor(),
		n3gNewNANDVisitor(),
		n3gEFINANDGeometryVisitor(),
		n3gEFIFirmwareRegionVisitor(),
		n3gNANDPlaneEraseECCVisitor(),
	}
}

// wraps the EFI volume at decrypted[offset:offset+size] in an IMG1, applies
// the visitors, and copies the patched body back in place
func patchN3GEFISlice(decrypted []byte, offset, size int, visitor VolumeVisitor) error {
	wrapped, err := image.MakeUnsigned(devices.Nano3, 0, decrypted[offset:(offset+size)])
	if err != nil {
		return fmt.Errorf("failed to wrap EFI: %w", err)
	}
	patched, err := defangEFI(visitor)(wrapped)
	if err != nil {
		return err
	}
	body := patched[n3gIMG1HeaderSize:]
	if len(body) > size {
		return fmt.Errorf("patched EFI volume grew from %d to %d bytes, past its reserved window at offset 0x%x - would overwrite whatever follows", size, len(body), offset)
	}
	copy(decrypted[offset:], body)
	return nil
}
