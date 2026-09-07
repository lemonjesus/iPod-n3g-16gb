# iPod Nano 3rd Generation 16GB NAND Patcher

This tool mods an iPod nano 3rd Generation to run on a 16 GB NAND flash chip. The stock firmware assumes the original chips' 4096-byte NAND pages; the replacement chip has 8192-byte pages and far more capacity, so the patcher bridges that mismatch in every firmware layer that touches NAND and teaches the drivers the new chip's geometry.

[The full story of how this was figured out is in the accompanying writeup.](https://tuckerosman.com/projects/16gb-ipod-nano) This project took me six years of on-again-off-again work and experimentation starting in 2020. It mostly took that long because I learned from zero about NAND internals, iPod firmware, and reverse engineering techniques. You can follow the journey in the writeup and the slow progress I made in the [iPod Nano Discord server](https://discord.gg/bah8hgkTQs).

A nano 3G running this firmware on the 16 GB chip boots RetailOS, reports 15 GB in Settings → About, and keeps its filesystem across a reboot. Long-term FTL health (sustained writes, wear levelling, power loss mid-write) is not yet proven, but theoretically very likely.

The original NAND chip has to be replaced with a 16 GB (128Gb) part. The patchset targets one specific chip - a Micron SLC with NAND ID `0xA701882C` and 8192-byte pages (encoded in `pkg/nand16gb/chip.go`) - and has no fallbacks. Other chips are not supported but with a tiny bit of elbow grease, it might be possible to adapt the patcher. MLC chips of this size are unlikely to ever work because the ECC engine might not be able to support the higher error correction requirements. If you figure out how to make it work with other chips, contributions are welcome.

# Building

You'll need Go and libusb. The patchset also assembles a handful of ARM trampolines from source at patch time, so you'll additionally need:

 - `arm-linux-gnueabi-as`, `-ld`, `-objcopy`, `-nm`

Everything in `pkg/nand16gb/asm` is assembly, so binutils is all that's required - no C compiler. On Debian/Ubuntu: `apt install binutils-arm-linux-gnueabi`. These aren't needed to build the `wInd3x` binary itself, only to actually run the patcher (they're invoked via `os/exec` when the patches are applied) - `go build` will succeed without them, but `cfw 16gb` (see below) will fail with a clear error if they're missing.

    $ go build ./cmd/wInd3x

# Running

Put your iPod into DFU mode by connecting it over USB, holding down menu+select until it reboots, blanks the screen, then shows the Apple logo, then blanks the screen again. The iPod should enumerate as 'DFU Device'. Then run:

    $ ./wInd3x cfw 16gb

This is the one command that does everything: downloads the stock firmware, decrypts and unpacks it just like upstream wInd3x, applies the full 16GB NAND patchset to the recovery and firmware images, and flashes them to the device over DFU. It needs network access on the first run (to fetch the stock IPSW) and takes a while the first time through (decryption is slow). Leave the iPod connected and don't unplug it until it finishes and reboots on its own.

`--firmware-only` (`-F`) skips the WTF/recovery DFU sends and just writes the firmware image (AUPD + RetailOS + disk mode + permanent EFI) to a device already in Disk mode - the fast iteration loop for changes to those layers. It needs the decrypted firmware cache to already be populated, so run the full command once first.

## Formatting the iPod afterwards

The restore leaves the data partition unformatted. Format **that partition only**:

    $ ./wInd3x cfw 16gb          # authors the partition table
    $ sudo mkfs.vfat -F 32 /dev/sdX1

Do not create the partition table yourself, and never format the whole-disk node. The firmware volume lives at LBA 63 in 4096-byte blocks and is not a file inside the filesystem; nothing on the device stops a data partition from being placed on top of it. A table that lets the two overlap does not fail - the iPod boots and works until a sync fills the filesystem far enough to reach the boot image, then eats it from the front. Resources go first, so games stop loading before booting breaks; once the MSE directory and osos are gone, the EFI's boot chain fails and you get the `bdsw` "please restore" screen with no way back except rewriting the firmware.

The tool authors the table itself, reserving 128 MiB at LBA 63 so the data partition starts at LBA 32831, and it reads the table back and re-reads the MSE directory to check the write landed. A full restore repartitions unconditionally; `--firmware-only` leaves an already-correct layout (and your data) alone, and repairs a bad one. `--no-repartition` turns that repair into an error instead.

`go run ./cmd/wInd3x cfw 16gb` works too if you'd rather skip the separate build step. The rest of the upstream wInd3x command set (decryption, NAND/NOR inspection, restore, ...) remains available for development.

# How It Works

On the first run, the tool downloads the stock WTF, recovery, and firmware images for the iPod nano 3G from Apple's IPSW servers and decrypts them using the iPod itself as a decryption oracle (a slow process, cached afterwards). With plaintext binaries in hand, it can patch in support for the 16 GB NAND chip.

The patches are installed through the normal restore process:

 1. The wInd3x exploit runs against DFU, leaving it willing to accept unsigned images. A defanged WTF (signature checks disabled) is sent and boots.
 1. The WTF waits for a recovery payload: a temporary EFI and disk mode binary that facilitate the rest of the restore. Both are patched for the 16 GB NAND, and both get saved to NOR - encrypted, but with our changes intact.
 1. The recovery payload boots like normal and launches disk mode, at which point the full firmware image is sent: the permanent EFI, Disk Mode, Diagnostic Mode, and RetailOS. All but Diagnostic Mode are patched.
 1. Once the restore completes, everything is persisted on the iPod - the mod is untethered.

## Where the patches live

- `pkg/nand16gb` is the chip patchset, one `patch_<layer>.go` file per firmware layer: disk mode, AUPD, RetailOS, and the EFI NAND driver (`patch_efi_nand.go`, which grows the driver's PE32 image and appends its trampolines). Disk mode, AUPD, and RetailOS carry byte-identical copies of the same ARM NAND driver (just at different addresses), so the `nand_*.S` trampolines - two-plane erase, both-plane bad-block scan, erased-page poison scrub - are shared, and each layer supplies its own hook addresses.
- The 4K/8K mismatch is bridged where each layer feels it: disk mode gets the SCSI executor and FTL read/write bridges (`diskmode_scsibridge.S`, `diskmode_ftlbridge.S`); RetailOS gets `osos_blockbridge.S`, because its storage executors compute `ratio = 4096 / pageSize`, which an 8 KiB page makes zero, multiplying every LBA and count by zero. The EFI driver is Thumb rather than ARM, so it gets its own implementation in `efi_nand.S`, including a 4 KB Block IO shim.
- `pkg/cfw/patch_n3g_efi.go` wires the EFI-side patches into the EFI volume, identically in the temporary recovery EFI and the permanent one: the ROM validator's signature check is disabled, the 16 GB chip descriptor is injected, the LBA-count divide's operands are swapped so the media reports `pageCount * 2` blocks, and the firmware volume's reserved region is doubled from 64 to 128 MiB.
- `pkg/cfw/defang_n3g.go` wires the layers together per restore stage.

Details on the trampolines and why the per-layer bridges can't share code are in `pkg/nand16gb/asm/README.md`.

# Credits

The exploit, as well as a lot of the code, is based on q3k's
[wInd3x](https://github.com/freemyipod/wInd3x) tool and exploit. Without that work, this would not have been possible - it contains a lot of patching goodies that would have been a pain to reimplement, not to mention the whole exploit itself is pretty nice.

LLMs were used to help write some of the patching code. This project has spanned multiple years, so the vast majority of this project was done and worked on without the help of AI, but the final mile of patching code was written with the assistance of LLMs. Every line of code was reviewed and tested by me regardless of who or what wrote it.

Like upstream wInd3x, this project is released under the GPLv2 (see `COPYING`).
