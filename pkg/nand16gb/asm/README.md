# Trampoline sources

Each file is named `<target>_<what>.S` so you know what patch does what where:

| prefix      | consumed by                            |
|-------------|----------------------------------------|
| `nand_`     | disk mode, AUPD, and RetailOS          |
| `diskmode_` | disk mode only                         |
| `osos_`     | RetailOS only                          |
| `efi_`      | the EFI NAND driver only               |

## The files

    nand_planeerase.S       two-plane erase
    nand_bbtscan.S          both-planes factory bad-block scan
    nand_erasedpage.S       erased-page poison scrub + GC tombstone suppression

    diskmode_scsibridge.S   4 KiB SCSI sectors over 8 KiB NAND pages
    diskmode_ftlbridge.S    4K<->8K scratch-RMW on the FTL read/write path

    osos_blockbridge.S      4 KiB logical blocks over 8 KiB FTL pages

    efi_nand.S              two-plane erase, ECC scrub, BBT scan and Block IO
                            for the EFI's NAND driver

`nand_*` are shared because disk mode, AUPD, and RetailOS each carry a byte-identical build of the same NAND driver, just in different places within the binary. They are fully parameterized: every address is a required `--defsym` to define where things should go. The two `*bridge` pairs solve the same problem for different layers but cannot share code: disk mode replaces whole functions taking five arguments (one on the stack) and returns normally, while RetailOS is entered by a branch planted mid-function over a `mul`, takes three live registers, and exits through the host function's own epilogue. `efi_nand.S` needs to be separate despite having similar patches because the EFI is THUMB.
