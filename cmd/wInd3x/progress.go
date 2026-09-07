package main

import (
	"github.com/schollz/progressbar/v3"

	"github.com/freemyipod/wInd3x/pkg/dfu"
	"github.com/freemyipod/wInd3x/pkg/exploit/decrypt"
)

// sendProgress wires a terminal progress bar into dfu.SendImage's progress
// callback.
func sendProgress(label string, total int) dfu.SendOption {
	bar := progressbar.DefaultBytes(int64(total), label)
	return dfu.SendOption{
		Progress: func(f float32) {
			bar.Set64(int64(f * float32(total)))
		},
	}
}

// decryptProgress wires a terminal progress bar into decrypt.Decrypt's
// progress callback.
func decryptProgress(label string, total int) decrypt.Option {
	bar := progressbar.DefaultBytes(int64(total), label)
	return decrypt.Option{
		Progress: func(f float32) {
			bar.Set64(int64(f * float32(total)))
		},
	}
}
