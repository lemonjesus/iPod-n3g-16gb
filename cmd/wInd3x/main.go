package main

import (
	"flag"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var rootCmd = &cobra.Command{
	Use:   "wInd3x",
	Short: "wInd3x is an exploit tool for the iPod Nano 3G/4G/5G",
	Long: `Allows to decrypt firmware files, generate DFU images and run unsigned DFU
images on the Nano 3G/4G/5G. This fork adds 'cfw 16gb': patch and flash the
firmware for a 16 GB NAND upgrade on the iPod nano 3G.

Copyright 2022 q3k, user890104. With help from zizzy and d42.

wInd3x comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
welcome to redistribute it under certain conditions; see COPYING file
accompanying distribution for details.`,
	SilenceUsage: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verboseLog {
			slog.SetLogLoggerLevel(slog.LevelDebug)
		}
	},
}

var verboseLog bool

func main() {
	makeDFUCmd.Flags().StringVarP(&makeDFUEntrypoint, "entrypoint", "e", "0x0", "Entrypoint offset for image (added to load address == 0x2200_0000)")
	makeDFUCmd.Flags().StringVarP(&makeDFUDeviceKind, "kind", "k", "", "Device kind (one of 'n4g', 'n5g')")
	decryptCmd.Flags().StringVarP(&decryptRecovery, "recovery", "r", "", "EXPERIMENTAL: Path to temporary file used for recovery when restarting the transfer")
	restoreCmd.Flags().BoolVarP(&restoreFull, "full", "f", false, "Perform full restore, including repartition and bootloader install. If true, you will have to manually reformat the main partition as FAT32, otherwise the device will seem bricked.")
	restoreCmd.Flags().StringVarP(&restoreVersion, "version", "V", "current", "Restore to some older version instead of 'current' from Apple. Use 'list' to show available.")
	mseExtractCmd.Flags().StringVarP(&extractDir, "out", "o", "", "Directory to extract to (default: current working directory)")
	cfw16gbCmd.Flags().BoolVarP(&cfw16gbFirmwareOnly, "firmware-only", "F", false, "Skip the WTF and recovery sends and only write the firmware image (AUPD + RetailOS + disk mode + permanent EFI) to a device already in Disk mode")
	cfw16gbCmd.Flags().BoolVar(&cfw16gbNoRepartition, "no-repartition", false, "Fail instead of repartitioning when the device's partition table lets the data filesystem overlap the firmware volume")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().BoolVarP(&verboseLog, "verbose", "v", false, "Enable verbose debug logging")
	rootCmd.AddCommand(haxDFUCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(makeDFUCmd)
	rootCmd.AddCommand(dumpCmd)
	rootCmd.AddCommand(decryptCmd)
	nandCmd.AddCommand(nandReadCmd)
	nandCmd.AddCommand(nandIdentifyCmd)
	rootCmd.AddCommand(nandCmd)
	norCmd.AddCommand(norReadCmd)
	rootCmd.AddCommand(norCmd)
	rootCmd.AddCommand(spewCmd)
	cfwCmd.AddCommand(cfw16gbCmd)
	cfwCmd.AddCommand(cfwRunCmd)
	cfwCmd.AddCommand(cfwSuperdiagsCmd)
	rootCmd.AddCommand(cfwCmd)
	rootCmd.AddCommand(restoreCmd)
	mseCmd.AddCommand(mseExtractCmd)
	rootCmd.AddCommand(mseCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.Execute()
}

func init() {
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
}

func parseNumber(s string) (uint32, error) {
	var err error
	var res uint64
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		res, err = strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid number")
		}
	} else {
		res, err = strconv.ParseUint(s, 10, 32)
		if err != nil {
			res, err = strconv.ParseUint(s, 16, 32)
			if err != nil {
				return 0, fmt.Errorf("invalid number")
			}
		}
	}
	return uint32(res), nil
}
