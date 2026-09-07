package nand16gb

import "fmt"

// imageSplicer assembles trampoline blobs one after another into a free region
// of a firmware image, refusing to write over anything that isn't already zero
// or to run past the region's ceiling.
type imageSplicer struct {
	layer   string           // "aupd" / "osos", for error messages
	img     []byte           // the image being patched, mutated in place
	workDir string           // scratch dir for the assembler
	next    uint32           // next free VA
	end     uint32           // ceiling: nothing may be written at or past this VA
	off     func(uint32) int // VA -> byte offset within img
}

// splice assembles asm/<srcName> at the current cursor with the given defsyms
// and copies it in, returning its symbol table.
func (s *imageSplicer) splice(srcName string, defsyms defsyms) (symtab, error) {
	va := (s.next + 3) &^ 3
	code, syms, err := assembleLinkARM(s.workDir, srcName, va, defsyms)
	if err != nil {
		return nil, fmt.Errorf("%s: assemble %s: %w", s.layer, srcName, err)
	}
	blobEnd := va + uint32(len(code))
	if blobEnd > s.end {
		return nil, fmt.Errorf("%s: %s (%d bytes @0x%x) ends 0x%x, past the patch region ceiling 0x%x",
			s.layer, srcName, len(code), va, blobEnd, s.end)
	}
	off := s.off(va)
	if off < 0 || off+len(code) > len(s.img) {
		return nil, fmt.Errorf("%s: %s at 0x%x overruns the image", s.layer, srcName, va)
	}
	for i, b := range s.img[off : off+len(code)] {
		if b != 0 {
			return nil, fmt.Errorf("%s: patch region 0x%x is not free (byte 0x%x != 0); pick another gap",
				s.layer, va+uint32(i), b)
		}
	}
	copy(s.img[off:off+len(code)], code)
	s.next = blobEnd
	return syms, nil
}
