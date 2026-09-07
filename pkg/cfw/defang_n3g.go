package cfw

import (
	"fmt"
	"log/slog"

	"github.com/freemyipod/wInd3x/pkg/devices"
	"github.com/freemyipod/wInd3x/pkg/nand16gb"
)

const (
	// Offsets within the N3G recovery (disk mode DFU) image.
	n3gRecoveryBootLogoOffset   = 0x127940
	n3gRecoveryBootLogoPatchLen = 0xC0
	n3gRecoveryEFIOffset        = 0x30A78
	n3gRecoveryEFISize          = 0x4FF50
	n3gRecoveryDiskModeOffset   = 0xE40B8

	// Another place the chip description shows up
	n3gRecoveryChipDescOffset = 0x1BD80

	// Offsets within the N3G firmware (OSOS/AUPD) binary.
	n3gFirmwareOsosOffset     = 0x4E07800
	n3gFirmwareAUPDOffset     = 0x5853000
	n3gFirmwareDiskModeOffset = 0x5939FB8

	n3gFirmwareBodyBase     = n3gFirmwareAUPDOffset + n3gIMG1HeaderSize
	n3gFirmwareEFIRelOffset = 0x33178
	n3gFirmwareEFISize      = 0x4FF50

	n3gFirmwareBootLogoRelOffset = 0x2C7C0
	n3gFirmwareBootLogoPatchLen  = 0xB40
)

var RecoveryDefangers = map[devices.Kind]Defanger{
	devices.Nano3: func(decrypted []byte) ([]byte, error) {
		slog.Info("Defanging N3G recovery...")

		// ====== Recovery Disk Mode ======
		// Visually show on Disk Mode with a white bar that the image has been modified.
		for i := 0; i < n3gRecoveryBootLogoPatchLen; i++ {
			decrypted[n3gRecoveryBootLogoOffset+i] = 0x00
		}

		diskflsh := decrypted[n3gRecoveryDiskModeOffset : n3gRecoveryDiskModeOffset+nand16gb.DiskModeBlobSize]
		if err := nand16gb.ApplyDiskModePatches(diskflsh); err != nil {
			return nil, fmt.Errorf("failed to apply disk-mode NAND patches: %w", err)
		}

		// The recovery image carries another copy of the chip descriptor outside the disk-mode blob.
		copy(decrypted[n3gRecoveryChipDescOffset:], nand16gb.ChipDescriptor)

		// ====== Temporary Recovery EFI ======
		err := patchN3GEFISlice(decrypted, n3gRecoveryEFIOffset, n3gRecoveryEFISize, MultipleVisitors(n3gEFIVisitors()))
		if err != nil {
			return nil, fmt.Errorf("failed to defang recovery EFI: %w", err)
		}

		return decrypted, nil
	},
}

var FirmwareDefangers = map[devices.Kind]Defanger{
	devices.Nano3: func(decrypted []byte) ([]byte, error) {
		slog.Info("Defanging N3G firmware...")

		// ====== AUPD ======
		// Draw a white bar across the AUPD boot logo to signal modification.
		for i := 0; i < n3gFirmwareBootLogoPatchLen; i++ {
			decrypted[n3gFirmwareBodyBase+n3gFirmwareBootLogoRelOffset+i] = 0xFF
		}

		if err := nand16gb.ApplyAUPDPatches(decrypted[n3gFirmwareAUPDOffset:]); err != nil {
			return nil, fmt.Errorf("failed to apply AUPD NAND patches: %w", err)
		}

		// ====== Persistent EFI Volume ======
		efiStart := n3gFirmwareBodyBase + n3gFirmwareEFIRelOffset
		err := patchN3GEFISlice(decrypted, efiStart, n3gFirmwareEFISize, MultipleVisitors(n3gEFIVisitors()))
		if err != nil {
			return nil, fmt.Errorf("failed to defang firmware EFI: %w", err)
		}

		// ====== Disk Mode ======
		firmwareDiskflsh := decrypted[n3gFirmwareDiskModeOffset : n3gFirmwareDiskModeOffset+nand16gb.DiskModeBlobSize]
		if err := nand16gb.ApplyDiskModePatches(firmwareDiskflsh); err != nil {
			return nil, fmt.Errorf("failed to apply firmware disk-mode NAND patches: %w", err)
		}

		// ====== RetailOS ======
		if err := nand16gb.ApplyRetailOSPatches(decrypted[n3gFirmwareOsosOffset:]); err != nil {
			return nil, fmt.Errorf("failed to apply RetailOS NAND patches: %w", err)
		}

		return decrypted, nil
	},
}
