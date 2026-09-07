package nand16gb

// ChipDescriptor is the raw device-table-entry encoding of the 16GB
// replacement NAND chip (Micron SLC, ID 0xA701882C)
var ChipDescriptor = []byte{
	0x2C, 0x88, 0x01, 0xA7, // NAND ID (0xA701882C, SLC part)
	0x02, 0x00, // bank count = 2
	0x00, 0x10, // blocks per bank = 4096 (chip's real 256-page blocks; 2*4096*256*8192 = 16 GiB)
	0x00, 0x01, // pages per block = 256 (chip's real single-plane block; planes interleave by block parity)
	0x10, 0x00, // pagesizefactor = 16 (16 * 512 = 8192 bytes)
	0xC0, 0x01, // oob size = 448
	0x01, 0x00, // byte 0x0e, as in the last entry of the stock device table
	0x8C, 0x00, // timing 0_0 = 140ns
	0x46, 0x00, // timing 0_1 = 70ns
	0x46, 0x00, // timing 0_2 = 70ns
	0x8C, 0x00, // timing 1_0 = 140ns
	0x46, 0x00, // timing 1_1 = 70ns
	0x46, 0x00, // timing 1_2 = 70ns
	0x04, 0x00, 0x00, 0x00, // initial bbt type
	0x20, 0x0F, // user blocks per bank 0xF20 (3872; 256-page geometry)
	0x00, 0x00, // padding
	0x02, 0x00, 0x00, 0x00, // vendor spec type = 2
	0x06,       // unused
	0x08,       // fil ecc refresh threshold
	0x00, 0x00, // padding
}
