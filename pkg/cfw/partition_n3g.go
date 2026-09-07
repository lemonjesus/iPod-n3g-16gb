package cfw

import (
	"encoding/binary"
	"fmt"
)

// The firmware volume is not a file inside the data filesystem: it lives at a
// fixed LBA that disk mode, the EFI and RetailOS all address directly.
const (
	// N3GFirmwareVolumeLBA is where disk mode writes the firmware volume and
	// where the EFI and RetailOS read it, in device blocks.
	N3GFirmwareVolumeLBA = 63

	// N3GFirmwarePartitionSize is how much to reserve for the firmware. It
	// matches the region n3gEFIFirmwareRegionVisitor establishes and clears the
	// ~94 MB image with headroom.
	N3GFirmwarePartitionSize = 128 << 20
)

// MBRPartition is one entry of the four in an MBR partition table, with LBAs in
// whatever unit the device reports.
type MBRPartition struct {
	Index int
	Type  byte
	Start uint32
	Size  uint32
}

// Empty reports whether the slot is unused. Apple uses type 0 for the firmware partition itself
func (p MBRPartition) Empty() bool { return p.Type == 0 && p.Size == 0 }

// End is the first LBA past the partition.
func (p MBRPartition) End() uint32 { return p.Start + p.Size }

func (p MBRPartition) String() string {
	return fmt.Sprintf("part%d type 0x%02x LBA %d-%d (%d blocks)", p.Index, p.Type, p.Start, p.End()-1, p.Size)
}

// ParseMBR reads the four partition entries out of LBA 0
func ParseMBR(block []byte) ([]MBRPartition, error) {
	if len(block) < 512 {
		return nil, fmt.Errorf("block is %d bytes, need at least 512", len(block))
	}
	if block[0x1fe] != 0x55 || block[0x1ff] != 0xaa {
		return nil, fmt.Errorf("no MBR signature at +0x1fe (got %02x%02x)", block[0x1fe], block[0x1ff])
	}
	parts := make([]MBRPartition, 4)
	for i := range parts {
		e := block[0x1be+i*16 : 0x1be+(i+1)*16]
		parts[i] = MBRPartition{
			Index: i,
			Type:  e[4],
			Start: binary.LittleEndian.Uint32(e[8:12]),
			Size:  binary.LittleEndian.Uint32(e[12:16]),
		}
	}
	return parts, nil
}

// CheckN3GLayout reports whether the table keeps the firmware volume to itself:
// one partition starting at the volume LBA and big enough to hold it, and no
// other partition reaching into that region.
func CheckN3GLayout(parts []MBRPartition, fwBlocks uint32) error {
	fwEnd := uint32(N3GFirmwareVolumeLBA) + fwBlocks

	var fw *MBRPartition
	for i := range parts {
		p := &parts[i]
		if p.Empty() {
			continue
		}
		if p.Start == N3GFirmwareVolumeLBA {
			fw = p
			continue
		}
		if p.Start < fwEnd {
			return fmt.Errorf("%s starts inside the firmware region (LBA %d-%d): "+
				"the filesystem and the boot image share blocks, so syncing overwrites the firmware",
				p, N3GFirmwareVolumeLBA, fwEnd-1)
		}
	}
	if fw == nil {
		return fmt.Errorf("no partition starts at LBA %d, so the firmware volume is not reserved",
			N3GFirmwareVolumeLBA)
	}
	if fw.Size < fwBlocks {
		return fmt.Errorf("%s is smaller than the %d blocks the firmware needs", fw, fwBlocks)
	}
	return nil
}
