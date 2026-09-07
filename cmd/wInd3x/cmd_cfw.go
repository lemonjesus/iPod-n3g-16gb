package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/freemyipod/wInd3x/pkg/app"
	"github.com/freemyipod/wInd3x/pkg/cache"
	"github.com/freemyipod/wInd3x/pkg/cfw"
	"github.com/freemyipod/wInd3x/pkg/devices"
	"github.com/freemyipod/wInd3x/pkg/dfu"
	"github.com/freemyipod/wInd3x/pkg/efi"
	"github.com/freemyipod/wInd3x/pkg/exploit/haxeddfu"
	"github.com/freemyipod/wInd3x/pkg/image"
	"github.com/freemyipod/wInd3x/pkg/mse"
	"github.com/freemyipod/wInd3x/pkg/usbms"
)

var cfwCmd = &cobra.Command{
	Use:   "cfw",
	Short: "Custom firmware generation and installation",
	Long:  "Build and install custom firmware. The main command is `cfw 16gb`: it applies the 16GB NAND patchset and flashes an iPod nano 3G. `run` and `superdiags` are dev helpers.",
}

type findVisitor struct {
	want  []string
	found []*efi.FirmwareFile
}

func (v *findVisitor) Done() error {
	return nil
}

func (v *findVisitor) VisitFile(file *efi.FirmwareFile) error {
	for _, section := range file.Sections {
		if section.Header().Type == efi.SectionTypeUserInterface {
			name := string(bytes.ReplaceAll(section.Raw(), []byte{0}, []byte{}))
			if slices.Contains(v.want, name) {
				slog.Debug("Found", "name", name)
				v.found = append(v.found, file)
			}
		}
	}
	return nil
}

func (v *findVisitor) VisitSection(section efi.Section) error {
	return nil
}

func superdiags(app *app.App) ([]byte, error) {
	diagb, err := cache.Get(app, cache.PayloadKindDiagsDecrypted)
	if err != nil {
		return nil, fmt.Errorf("when getting diags: %w", err)
	}
	diagi, err := image.Read(bytes.NewReader(diagb))
	if err != nil {
		return nil, fmt.Errorf("when reading diags: %w", err)
	}
	diag, err := efi.ReadVolume(efi.NewNestedReader(diagi.Body))
	if err != nil {
		return nil, fmt.Errorf("when reading diags fv: %w", err)
	}
	bootb, err := cache.Get(app, cache.PayloadKindBootloaderDecrypted)
	if err != nil {
		return nil, fmt.Errorf("when getting bootloader: %w", err)
	}
	booti, err := image.Read(bytes.NewReader(bootb))
	if err != nil {
		return nil, fmt.Errorf("when reading bootloader: %w", err)
	}
	boot, err := efi.ReadVolume(efi.NewNestedReader(booti.Body))
	if err != nil {
		return nil, fmt.Errorf("when reading bootloader fv: %w", err)
	}

	fv := &findVisitor{
		want: []string{
			"DiskIoDxe",
			"Partition",
			"Image1FSReadOnly",
			"Nand",
		},
	}
	if err := cfw.VisitVolume(boot, fv); err != nil {
		return nil, fmt.Errorf("when visiting bootloader: %w", err)
	}
	if want, got := len(fv.want), len(fv.found); want != got {
		return nil, fmt.Errorf("did not find all requested modules (wanted %v, got %d)", fv.want, len(fv.found))
	}

	slog.Debug("Before append", "files", len(diag.Files))
	diag.Files = append(diag.Files, fv.found...)
	slog.Debug("After append", "files", len(diag.Files))
	diagb, err = diag.Serialize()
	if err != nil {
		return nil, fmt.Errorf("could not serialize superdiags fv: %w", err)
	}
	diagbi, err := image.MakeUnsigned(diagi.DeviceKind, diagi.Header.Entrypoint, diagb)
	if err != nil {
		return nil, fmt.Errorf("could not make superdiags image: %w", err)
	}
	return diagbi, nil
}

var cfwSuperdiagsCmd = &cobra.Command{
	Use:   "superdiags",
	Short: "Run superdiags",
	Long:  "Run superdiags (diag with extra Nand driver). If your iPod has a connected DCSD cable, you'll be able to access a console over it.",
	RunE: func(cmd *cobra.Command, args []string) error {

		app, err := newDFU()
		if err != nil {
			return err
		}
		defer app.Close()

		diags, err := superdiags(&app.App)
		if err != nil {
			return err
		}

		wtf, err := cache.Get(&app.App, cache.PayloadKindWTFDefanged)
		if err != nil {
			return err
		}

		if err := haxeddfu.Trigger(app.Usb, app.Ep, false); err != nil {
			return fmt.Errorf("failed to run wInd3x exploit: %w", err)
		}
		slog.Info("Sending defanged WTF...")
		if err := dfu.SendImage(app.Usb, wtf, app.Desc.Kind.DFUVersion(), sendProgress("Sending WTF", len(wtf))); err != nil {
			return fmt.Errorf("failed to send image: %w", err)
		}

		slog.Info("Waiting 10s for device to switch to WTF mode...")
		ctx, ctxC := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer ctxC()
		if err := app.waitSwitch(ctx, devices.WTF); err != nil {
			return fmt.Errorf("device did not switch to WTF mode: %w", err)
		}
		time.Sleep(time.Second)

		slog.Info("Sending diags...")
		for i := 0; i < 10; i++ {
			err = dfu.SendImage(app.Usb, diags, app.Desc.Kind.DFUVersion(), sendProgress("Sending diags", len(diags)))
			if err == nil {
				break
			} else {
				slog.Error("Error when sending diags", "err", err)
				time.Sleep(time.Second)
			}
		}
		if err != nil {
			return err
		}

		slog.Info("Done.")

		return nil
	},
}

var (
	cfw16gbFirmwareOnly  bool
	cfw16gbNoRepartition bool
)

// ensureN3GPartitioning gives the firmware volume a partition of its own before
// any firmware is written into it.
func ensureN3GPartitioning(h *usbms.Host, force bool) error {
	lastLBA, blockSize, err := h.ReadCapacity()
	if err != nil {
		return fmt.Errorf("could not read device capacity: %w", err)
	}
	if blockSize == 0 || cfw.N3GFirmwarePartitionSize%int(blockSize) != 0 {
		return fmt.Errorf("device reports a %d-byte block, which does not divide the %d-byte firmware partition",
			blockSize, cfw.N3GFirmwarePartitionSize)
	}
	fwBlocks := uint32(cfw.N3GFirmwarePartitionSize / int(blockSize))
	slog.Info("Device geometry", "blocks", lastLBA+1, "blockSize", blockSize)

	var layoutErr error
	if mbr, err := h.ReadBlocks(0, 1, blockSize); err != nil {
		layoutErr = fmt.Errorf("could not read the partition table: %w", err)
	} else if parts, err := cfw.ParseMBR(mbr); err != nil {
		layoutErr = err
	} else {
		layoutErr = cfw.CheckN3GLayout(parts, fwBlocks)
	}

	if layoutErr == nil && !force {
		slog.Info("Partition layout already reserves the firmware volume, leaving it alone",
			"firmwareLBA", cfw.N3GFirmwareVolumeLBA, "dataLBA", cfw.N3GFirmwareVolumeLBA+fwBlocks)
		return nil
	}
	if layoutErr != nil {
		slog.Warn("Partition layout is unsafe", "problem", layoutErr)
		if cfw16gbNoRepartition {
			return fmt.Errorf("refusing to write firmware onto an unsafe layout (%w); "+
				"drop --no-repartition to have disk mode author a correct table", layoutErr)
		}
		slog.Warn("Repartitioning - THIS ERASES THE DATA PARTITION")
	}

	slog.Info("Reserving firmware partition...", "mib", cfw.N3GFirmwarePartitionSize>>20)
	if err := h.IPodRepartition(cfw.N3GFirmwarePartitionSize); err != nil {
		return fmt.Errorf("repartitioning failed: %w", err)
	}

	mbr, err := h.ReadBlocks(0, 1, blockSize)
	if err != nil {
		return fmt.Errorf("could not read back the partition table: %w", err)
	}
	parts, err := cfw.ParseMBR(mbr)
	if err != nil {
		return fmt.Errorf("could not parse the partition table after repartitioning: %w", err)
	}
	if err := cfw.CheckN3GLayout(parts, fwBlocks); err != nil {
		return fmt.Errorf("repartitioning did not produce a safe layout: %w", err)
	}
	for _, p := range parts {
		if !p.Empty() {
			slog.Info("Partition", "layout", p.String())
		}
	}
	slog.Info("Firmware volume reserved",
		"firmwareLBA", cfw.N3GFirmwareVolumeLBA, "blocks", fwBlocks,
		"dataLBA", cfw.N3GFirmwareVolumeLBA+fwBlocks)
	return nil
}

// verifyN3GFirmwareVolume reads the MSE volume header and directory back off the device
func verifyN3GFirmwareVolume(h *usbms.Host, blockSize uint32) error {
	base := uint32(cfw.N3GFirmwareVolumeLBA)
	hdr, err := h.ReadBlocks(base, 1, blockSize)
	if err != nil {
		return fmt.Errorf("could not read the volume header at LBA %d: %w", base, err)
	}
	if !bytes.Contains(hdr[:0x100], []byte("Copyright")) {
		return fmt.Errorf("no MSE guard string at LBA %d; the firmware volume is not where the EFI looks for it", base)
	}
	var vh mse.VolumeHeader
	if err := binary.Read(bytes.NewReader(hdr[0x100:]), binary.LittleEndian, &vh); err != nil {
		return fmt.Errorf("could not read the volume header: %w", err)
	}
	if vh.ID.String() != "[hi]" {
		return fmt.Errorf("volume header id is %q, want \"[hi]\"", vh.ID.String())
	}

	// The directory sits one block past DirectoryOffset: every MSE reader
	// computes DirectoryOffset + BlockSize. DirectoryOffset is a byte offset.
	dirLBA := base + vh.DirectoryOffset/blockSize + 1
	dir, err := h.ReadBlocks(dirLBA, 1, blockSize)
	if err != nil {
		return fmt.Errorf("could not read the directory at LBA %d: %w", dirLBA, err)
	}
	var names []string
	for i := 0; i < 16; i++ {
		var fh mse.FileHeader
		if err := binary.Read(bytes.NewReader(dir[i*40:(i+1)*40]), binary.LittleEndian, &fh); err != nil {
			return fmt.Errorf("could not read directory entry %d: %w", i, err)
		}
		if fh.Valid() {
			names = append(names, fh.Name.String())
		}
	}
	slog.Info("Firmware volume verified", "directoryLBA", dirLBA, "entries", names)

	// BDS boots only if rsrc and osos load; anything else shows bdsw and falls through to disk mode.
	for _, want := range []string{"rsrc", "osos"} {
		if !slices.Contains(names, want) {
			return fmt.Errorf("directory has no %q entry, so BDS will show bdsw; found %v", want, names)
		}
	}
	return nil
}

// writeN3GFirmware writes the patched firmware image to a device already in
// Disk mode, then resets it. Shared by cfw 16gb and its --firmware-only mode.
func writeN3GFirmware(a *desktopApp, firmware []byte, repartition bool) error {
	h := usbms.Host{
		Endpoints: a.MSEndpoints,
	}
	di, err := h.IPodDeviceInformation()
	if err != nil {
		slog.Error("Could not get device information", "err", err)
	} else {
		fmt.Printf("SerialNumber: %s\n", di.SerialNumber)
		fmt.Printf("     BuildID: %s\n", di.BuildID)
	}

	if len(firmware) > cfw.N3GFirmwarePartitionSize {
		return fmt.Errorf("firmware is %d bytes, larger than the %d-byte firmware partition",
			len(firmware), cfw.N3GFirmwarePartitionSize)
	}
	if err := ensureN3GPartitioning(&h, repartition); err != nil {
		return err
	}

	slog.Info("Writing firmware...")
	if err := h.IPodUpdateSendFull(usbms.IPodUpdateFirmware, firmware); err != nil {
		return fmt.Errorf("writing firmware failed: %w", err)
	}

	verifyErr := error(nil)
	if _, blockSize, err := h.ReadCapacity(); err != nil {
		slog.Warn("Could not re-read capacity, skipping verification", "err", err)
	} else {
		verifyErr = verifyN3GFirmwareVolume(&h, blockSize)
	}

	slog.Info("Resetting...")
	if err := h.IPodFinalize(true); err != nil {
		return fmt.Errorf("rebooting failed: %w", err)
	}
	if verifyErr != nil {
		return fmt.Errorf("firmware volume did not verify after writing: %w", verifyErr)
	}

	slog.Info("Done.")
	slog.Info("Format the DATA partition only (the second one) - never the whole-disk node, " +
		"and do not re-create the partition table: that is what puts the filesystem on top of the firmware.")
	return nil
}

var cfw16gbCmd = &cobra.Command{
	Use:   "16gb",
	Short: "Flash 16GB NAND firmware to an iPod nano 3G",
	Long: "Download, decrypt, patch, and flash recovery and firmware to an iPod nano 3G.\n\n" +
		"With --firmware-only, skip the WTF/recovery DFU sends and just write the " +
		"firmware image (AUPD + RetailOS/OSOS) to a device already in Disk mode - " +
		"the fast iteration loop for changes to those two. Requires the decrypted " +
		"firmware cache to already be populated (run once without the flag first).",
	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		if cfw16gbFirmwareOnly {
			app, err := newAny()
			if err != nil {
				return err
			}
			defer app.Close()

			if app.InterfaceKind != devices.Disk {
				return fmt.Errorf("--firmware-only needs a device already in Disk mode, but found it in %v mode; "+
					"run without the flag to send WTF and recovery first", app.InterfaceKind)
			}
			slog.Info("Found device", "device", app.Desc.Kind, "interface", app.InterfaceKind)

			firmware, err := cache.Get(&app.App, cache.PayloadKindFirmwareDefanged)
			if err != nil {
				return err
			}
			return writeN3GFirmware(app, firmware, false)
		}

		app, err := newDFU()
		if err != nil {
			return err
		}
		defer app.Close()

		if err := haxeddfu.Trigger(app.Usb, app.Ep, false); err != nil {
			return fmt.Errorf("failed to run wInd3x exploit: %w", err)
		}

		wtf, err := cache.Get(&app.App, cache.PayloadKindWTFDefanged)
		if err != nil {
			return err
		}

		recovery, err := cache.Get(&app.App, cache.PayloadKindRecoveryDefanged)
		if err != nil {
			return err
		}

		firmware, err := cache.Get(&app.App, cache.PayloadKindFirmwareDefanged)
		if err != nil {
			return err
		}

		slog.Info("Sending defanged WTF...")
		if err := dfu.SendImage(app.Usb, wtf, app.Desc.Kind.DFUVersion(), sendProgress("Sending WTF", len(wtf))); err != nil {
			return fmt.Errorf("failed to send WTF: %w", err)
		}

		slog.Info("Waiting 10s for device to switch to WTF mode...")
		ctx, ctxC := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer ctxC()
		if err := app.waitSwitch(ctx, devices.WTF); err != nil {
			return fmt.Errorf("device did not switch to WTF mode: %w", err)
		}
		time.Sleep(time.Second)

		slog.Info("Sending defanged recovery...")
		for i := 0; i < 10; i++ {
			err = dfu.SendImage(app.Usb, recovery, app.Desc.Kind.DFUVersion(), sendProgress("Sending recovery", len(recovery)))
			if err == nil {
				break
			}
			slog.Error("Error sending recovery", "err", err)
			time.Sleep(time.Second)
		}

		slog.Info("Waiting 60s for device to switch to Disk mode...")
		ctx2, ctx2C := context.WithTimeout(cmd.Context(), 60*time.Second)
		defer ctx2C()
		if err := app.waitSwitch(ctx2, devices.Disk); err != nil {
			return fmt.Errorf("device did not switch to Disk mode: %w", err)
		}
		time.Sleep(time.Second)

		return writeN3GFirmware(app, firmware, true)
	},
}

var cfwRunCmd = &cobra.Command{
	Use:   "run [firmware]",
	Short: "Run CFW",
	Long:  "Run CFW based on modified WTF and firmware (eg. modified OSOS or u-boot)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		app, err := newDFU()
		if err != nil {
			return err
		}
		defer app.Close()

		fwb, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}

		wtf, err := cache.Get(&app.App, cache.PayloadKindWTFDefanged)
		if err != nil {
			return err
		}

		if err := haxeddfu.Trigger(app.Usb, app.Ep, false); err != nil {
			return fmt.Errorf("failed to run wInd3x exploit: %w", err)
		}
		slog.Info("Sending defanged WTF...")
		if err := dfu.SendImage(app.Usb, wtf, app.Desc.Kind.DFUVersion(), sendProgress("Sending WTF", len(wtf))); err != nil {
			return fmt.Errorf("failed to send image: %w", err)
		}

		_, err = image.Read(bytes.NewReader(fwb))
		switch {
		case err == nil:
		case err == image.ErrNotImage1:
			fallthrough
		case len(fwb) < 0x400:
			slog.Info("Given firmware file is not IMG1, packing into one...")
			fwb, err = image.MakeUnsigned(app.Desc.Kind, 0, fwb)
			if err != nil {
				return err
			}
		default:
			return err
		}

		slog.Info("Waiting 10s for device to switch to WTF mode...")
		ctx, ctxC := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer ctxC()
		if err := app.waitSwitch(ctx, devices.WTF); err != nil {
			return fmt.Errorf("device did not switch to WTF mode: %w", err)
		}
		time.Sleep(time.Second)

		slog.Info("Sending firmware...")
		for i := 0; i < 10; i++ {
			err = dfu.SendImage(app.Usb, fwb, app.Desc.Kind.DFUVersion(), sendProgress("Sending firmware", len(fwb)))
			if err == nil {
				break
			} else {
				slog.Error("Error when sending firmware", "err", err)
				time.Sleep(time.Second)
			}
		}
		if err != nil {
			return err
		}

		slog.Info("Done.")

		return nil
	},
}
