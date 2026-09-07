package cache

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/adrg/xdg"

	"github.com/freemyipod/wInd3x/pkg/app"
	"github.com/freemyipod/wInd3x/pkg/cfw"
	"github.com/freemyipod/wInd3x/pkg/devices"
	"github.com/freemyipod/wInd3x/pkg/exploit/decrypt"
	"github.com/freemyipod/wInd3x/pkg/image"
	"github.com/freemyipod/wInd3x/pkg/mse"
)

type FS interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte) error
	Remove(path string) error
	Exists(path string) (bool, error)
}

type hostPathStore struct {
	root string
}

var Store FS = &hostPathStore{path.Join(xdg.DataHome, "wInd3x-16")}

func (h *hostPathStore) ReadFile(p string) ([]byte, error) {
	return os.ReadFile(path.Join(h.root, p))
}

func (h *hostPathStore) WriteFile(p string, data []byte) error {
	p = path.Join(h.root, p)
	parent := filepath.Dir(p)
	os.MkdirAll(parent, 0755)

	return os.WriteFile(p, data, 0644)
}

func (h *hostPathStore) Remove(p string) error {
	return os.Remove(path.Join(h.root, p))
}

func (h *hostPathStore) Exists(p string) (bool, error) {
	_, err := os.Stat(path.Join(h.root, p))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

var ReverseProxy *url.URL

type PayloadKind string

const (
	PayloadKindWTFUpstream       PayloadKind = "wtf-upstream"
	PayloadKindWTFDecrypted      PayloadKind = "wtf-decrypted"
	PayloadKindWTFDecryptedCache PayloadKind = "wtf-decrypted-cache"
	PayloadKindWTFDefanged       PayloadKind = "wtf-defanged"

	PayloadKindRecoveryUpstream      PayloadKind = "recovery-upstream"
	PayloadKindRecoveryDecrypted     PayloadKind = "recovery-decrypted"
	PayloadKindRecoveryDecryptedCache PayloadKind = "recovery-decrypted-cache"
	PayloadKindRecoveryDefanged      PayloadKind = "recovery-defanged"

	PayloadKindFirmwareUpstream      PayloadKind = "firmware-upstream"
	PayloadKindFirmwareDecrypted     PayloadKind = "firmware-decrypted"
	PayloadKindFirmwareDecryptedCache PayloadKind = "firmware-decrypted-cache"
	PayloadKindFirmwareDefanged      PayloadKind = "firmware-defanged"

	PayloadKindBootloaderUpstream       PayloadKind = "bootloader-upstream"
	PayloadKindBootloaderDecrypted      PayloadKind = "bootloader-decrypted"
	PayloadKindBootloaderDecryptedCache PayloadKind = "bootloader-decrypted-cache"

	PayloadKindRetailOSUpstream       PayloadKind = "retailos-upstream"
	PayloadKindRetailOSDecrypted      PayloadKind = "retailos-decrypted"
	PayloadKindRetailOSCustomized     PayloadKind = "retailos-customized"
	PayloadKindRetailOSDecryptedCache PayloadKind = "retailos-decrypted-cache"

	PayloadKindDiagsUpstream       PayloadKind = "diags-upstream"
	PayloadKindDiagsDecrypted      PayloadKind = "diags-decrypted"
	PayloadKindDiagsDecryptedCache PayloadKind = "diags-decrypted-cache"

	PayloadKindJingleXML PayloadKind = "jinglexml"
)

type GetOption struct {
	Progress func(float32)
}

type downloadMonitor struct {
	done         uint
	total        uint
	prevCallback float32
	callback     func(float32)
}

func (d *downloadMonitor) Write(data []byte) (int, error) {
	d.done += uint(len(data))
	percent := float32(d.done) / float32(d.total)
	if percent != d.prevCallback && d.callback != nil {
		d.callback(percent)
		d.prevCallback = percent
	}
	return len(data), nil
}

func getPayloadFromPhobosIPSW(pk PayloadKind, dk devices.Kind, urlStr string, options ...GetOption) error {
	var progress func(float32) = nil
	for _, option := range options {
		if option.Progress != nil {
			progress = option.Progress
		}
	}
	slog.Info("Downloading IPSW...", "kind", pk, "url", urlStr)

	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("could not parse URL %q: %w", urlStr, err)
	}
	if ReverseProxy != nil {
		u.Host = ReverseProxy.Host
		u.Scheme = ReverseProxy.Scheme
	}

	resp, err := http.Get(u.String())
	if err != nil {
		return fmt.Errorf("could not download IPSW: %w", err)
	}

	dlMonitor := &downloadMonitor{
		total:    uint(resp.ContentLength),
		callback: progress,
	}
	body, err := io.ReadAll(io.TeeReader(resp.Body, dlMonitor))
	if err != nil {
		return fmt.Errorf("could not download IPSW: %w", err)
	}
	z, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("could not parse IPSW: %w", err)
	}

	var want *regexp.Regexp
	switch pk {
	case PayloadKindWTFUpstream:
		want = regexp.MustCompile(`^firmware/dfu/wtf.*release\.dfu$`)
	case PayloadKindRecoveryUpstream:
		want = regexp.MustCompile(`^firmware/dfu/firmware.*release\.dfu$`)
	case PayloadKindFirmwareUpstream, PayloadKindRetailOSUpstream, PayloadKindDiagsUpstream:
		want = regexp.MustCompile(`^firmware.*$`)
	case PayloadKindBootloaderUpstream:
		want = regexp.MustCompile(`^n.*\.bootloader.*\.rb3$`)
	default:
		return fmt.Errorf("don't know file path for %s", pk)
	}
	var fname string
	for _, f := range z.File {
		if want.MatchString(strings.ToLower(f.Name)) {
			fname = f.Name
		}
	}
	if fname == "" {
		return fmt.Errorf("expected file not found in IPSW")
	}
	f, err := z.Open(fname)
	if err != nil {
		return fmt.Errorf("could not open %q in IPSW: %w", fname, err)
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read %q from IPSW: %w", fname, err)
	}

	switch pk {
	case PayloadKindRetailOSUpstream, PayloadKindDiagsUpstream:
		m, err := mse.Parse(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("could not parse firmware: %w", err)
		}
		fname := ""
		switch pk {
		case PayloadKindRetailOSUpstream:
			fname = "osos"
		case PayloadKindDiagsUpstream:
			fname = "diag"
		}
		mf := m.FileByName(fname)
		if mf == nil {
			return fmt.Errorf("no %q in firmware", fname)
		}
		data = mf.Data
	}

	fspath := pathFor(&dk, pk, urlStr)
	if err := Store.WriteFile(fspath, data); err != nil {
		return fmt.Errorf("could not write: %w", err)
	}
	return nil
}

func getBootloaderDecrypted(app *app.App, options ...GetOption) error {
	var progress func(float32) = nil
	for _, option := range options {
		if option.Progress != nil {
			progress = option.Progress
		}
	}

	encrypted, err := Get(app, PayloadKindBootloaderUpstream)
	if err != nil {
		return err
	}
	img1, err := image.Read(bytes.NewReader(encrypted))
	if err != nil {
		return fmt.Errorf("could not parse WTF IMG1: %w", err)
	}

	recovery := pathFor(&app.Desc.Kind, PayloadKindBootloaderDecryptedCache, "")

	var decryptOptions []decrypt.Option
	if progress != nil {
		decryptOptions = append(decryptOptions, decrypt.Option{Progress: progress})
	}
	decrypted, err := decrypt.Decrypt(app, img1.Body, recovery, decryptOptions...)
	if err != nil {
		return fmt.Errorf("could not decrypt bootloader: %w", err)
	}

	wrapper, err := image.MakeUnsigned(app.Desc.Kind, img1.Header.Entrypoint, decrypted)
	if err != nil {
		return fmt.Errorf("could not re-pack decrypted bootloader: %w", err)
	}

	fspath := pathFor(&app.Desc.Kind, PayloadKindBootloaderDecrypted, "")
	if err := Store.WriteFile(fspath, wrapper); err != nil {
		return fmt.Errorf("could not write bootloader: %w", err)
	}
	Store.Remove(recovery)
	return nil
}

func getWTFDecrypted(app *app.App, options ...GetOption) error {
	var progress func(float32) = nil
	for _, option := range options {
		if option.Progress != nil {
			progress = option.Progress
		}
	}

	encrypted, err := Get(app, PayloadKindWTFUpstream)
	if err != nil {
		return err
	}
	img1, err := image.Read(bytes.NewReader(encrypted))
	if err != nil {
		return fmt.Errorf("could not parse WTF IMG1: %w", err)
	}

	recovery := pathFor(&app.Desc.Kind, PayloadKindWTFDecryptedCache, "")

	var decryptOptions []decrypt.Option
	if progress != nil {
		decryptOptions = append(decryptOptions, decrypt.Option{Progress: progress})
	}
	decrypted, err := decrypt.Decrypt(app, img1.Body, recovery, decryptOptions...)
	if err != nil {
		return fmt.Errorf("could not decrypt WTF: %w", err)
	}

	wrapper, err := image.MakeUnsigned(app.Desc.Kind, img1.Header.Entrypoint, decrypted)
	if err != nil {
		return fmt.Errorf("could not re-pack decrypted WTF: %w", err)
	}

	fspath := pathFor(&app.Desc.Kind, PayloadKindWTFDecrypted, "")
	if err := Store.WriteFile(fspath, wrapper); err != nil {
		return fmt.Errorf("could not write WTF: %w", err)
	}
	Store.Remove(recovery)
	return nil
}

func getRetailOSDecrypted(app *app.App, options ...GetOption) error {
	var progress func(float32) = nil
	for _, option := range options {
		if option.Progress != nil {
			progress = option.Progress
		}
	}

	encrypted, err := Get(app, PayloadKindRetailOSUpstream)
	if err != nil {
		return err
	}
	img1, err := image.Read(bytes.NewReader(encrypted))
	if err != nil {
		return fmt.Errorf("could not parse RetailOS IMG1: %w", err)
	}

	recovery := pathFor(&app.Desc.Kind, PayloadKindRetailOSDecryptedCache, "")

	var decryptOptions []decrypt.Option
	if progress != nil {
		decryptOptions = append(decryptOptions, decrypt.Option{Progress: progress})
	}
	decrypted, err := decrypt.Decrypt(app, img1.Body, recovery, decryptOptions...)
	if err != nil {
		return fmt.Errorf("could not decrypt RetailOS: %w", err)
	}

	wrapper, err := image.MakeUnsigned(app.Desc.Kind, img1.Header.Entrypoint, decrypted)
	if err != nil {
		return fmt.Errorf("could not re-pack decrypted RetailOS: %w", err)
	}

	fspath := pathFor(&app.Desc.Kind, PayloadKindRetailOSDecrypted, "")
	if err := Store.WriteFile(fspath, wrapper); err != nil {
		return fmt.Errorf("could not write RetailOS: %w", err)
	}
	Store.Remove(recovery)
	return nil
}

func getDiagsDecrypted(app *app.App, options ...GetOption) error {
	var progress func(float32) = nil
	for _, option := range options {
		if option.Progress != nil {
			progress = option.Progress
		}
	}

	encrypted, err := Get(app, PayloadKindDiagsUpstream)
	if err != nil {
		return err
	}
	img1, err := image.Read(bytes.NewReader(encrypted))
	if err != nil {
		return fmt.Errorf("could not parse diag IMG1: %w", err)
	}

	recovery := pathFor(&app.Desc.Kind, PayloadKindDiagsDecryptedCache, "")

	var decryptOptions []decrypt.Option
	if progress != nil {
		decryptOptions = append(decryptOptions, decrypt.Option{Progress: progress})
	}
	decrypted, err := decrypt.Decrypt(app, img1.Body, recovery, decryptOptions...)
	if err != nil {
		return fmt.Errorf("could not decrypt diag: %w", err)
	}

	wrapper, err := image.MakeUnsigned(app.Desc.Kind, img1.Header.Entrypoint, decrypted)
	if err != nil {
		return fmt.Errorf("could not re-pack decrypted diag: %w", err)
	}

	fspath := pathFor(&app.Desc.Kind, PayloadKindDiagsDecrypted, "")
	if err := Store.WriteFile(fspath, wrapper); err != nil {
		return fmt.Errorf("could not write diag: %w", err)
	}
	Store.Remove(recovery)
	return nil
}

func getWTFDefanged(app *app.App, options ...GetOption) ([]byte, error) {
	defanger, ok := cfw.WTFDefangers[app.Desc.Kind]
	if !ok {
		return nil, fmt.Errorf("don't know how to defang a %s", app.Desc.Kind)
	}

	decrypted, err := Get(app, PayloadKindWTFDecrypted)
	if err != nil {
		return nil, err
	}
	defanged, err := defanger(decrypted)
	if err != nil {
		return nil, fmt.Errorf("defanging failed: %w", err)
	}
	fspath := pathFor(&app.Desc.Kind, PayloadKindWTFDefanged, "")
	if err := Store.WriteFile(fspath, defanged); err != nil {
		slog.Warn("Could not write defanged WTF to disk", "err", err)
	}
	return defanged, nil
}

func getRecoveryDecrypted(app *app.App, options ...GetOption) error {
	var progress func(float32) = nil
	for _, option := range options {
		if option.Progress != nil {
			progress = option.Progress
		}
	}

	encrypted, err := Get(app, PayloadKindRecoveryUpstream)
	if err != nil {
		return err
	}
	img1, err := image.Read(bytes.NewReader(encrypted))
	if err != nil {
		return fmt.Errorf("could not parse Recovery IMG1: %w", err)
	}

	recoveryCache := pathFor(&app.Desc.Kind, PayloadKindRecoveryDecryptedCache, "")

	var decryptOptions []decrypt.Option
	if progress != nil {
		decryptOptions = append(decryptOptions, decrypt.Option{Progress: progress})
	}
	decrypted, err := decrypt.Decrypt(app, img1.Body, recoveryCache, decryptOptions...)
	if err != nil {
		return fmt.Errorf("could not decrypt Recovery: %w", err)
	}

	wrapper, err := image.MakeUnsigned(app.Desc.Kind, img1.Header.Entrypoint, decrypted)
	if err != nil {
		return fmt.Errorf("could not re-pack decrypted Recovery: %w", err)
	}

	fspath := pathFor(&app.Desc.Kind, PayloadKindRecoveryDecrypted, "")
	if err := Store.WriteFile(fspath, wrapper); err != nil {
		return fmt.Errorf("could not write Recovery: %w", err)
	}
	Store.Remove(recoveryCache)
	return nil
}

func getRecoveryDefanged(app *app.App, options ...GetOption) ([]byte, error) {
	defanger, ok := cfw.RecoveryDefangers[app.Desc.Kind]
	if !ok {
		return nil, fmt.Errorf("don't know how to defang recovery for %s", app.Desc.Kind)
	}

	decrypted, err := Get(app, PayloadKindRecoveryDecrypted)
	if err != nil {
		return nil, err
	}
	defanged, err := defanger(decrypted)
	if err != nil {
		return nil, fmt.Errorf("defanging recovery failed: %w", err)
	}
	fspath := pathFor(&app.Desc.Kind, PayloadKindRecoveryDefanged, "")
	if err := Store.WriteFile(fspath, defanged); err != nil {
		slog.Warn("Could not write defanged recovery to disk", "err", err)
	}
	return defanged, nil
}

func getFirmwareDecrypted(app *app.App, options ...GetOption) error {
	encrypted, err := Get(app, PayloadKindFirmwareUpstream)
	if err != nil {
		return err
	}

	// Decrypt OSOS (hardcoded offsets for N3G firmware layout).
	ososCachePath := pathFor(&app.Desc.Kind, PayloadKindFirmwareDecryptedCache, "osos")
	var ososDecrypted []byte
	if exists, _ := Store.Exists(ososCachePath); exists {
		slog.Info("Using cached OSOS")
		ososDecrypted, err = Store.ReadFile(ososCachePath)
		if err != nil {
			return fmt.Errorf("could not read cached OSOS: %w", err)
		}
	} else {
		ososImg, err := image.Read(bytes.NewReader(encrypted[0x4E07000 : 0x4E07000+0xA4A9D3+0x800]))
		if err != nil {
			return fmt.Errorf("could not parse OSOS IMG1: %w", err)
		}
		ososDecrypted, err = decrypt.Decrypt(app, ososImg.Body, "")
		if err != nil {
			return fmt.Errorf("could not decrypt OSOS: %w", err)
		}
		if err := Store.WriteFile(ososCachePath, ososDecrypted); err != nil {
			return fmt.Errorf("could not cache OSOS: %w", err)
		}
	}

	// Decrypt AUPD (hardcoded offsets for N3G firmware layout).
	aupdCachePath := pathFor(&app.Desc.Kind, PayloadKindFirmwareDecryptedCache, "aupd")
	var aupdDecrypted []byte
	if exists, _ := Store.Exists(aupdCachePath); exists {
		slog.Info("Using cached AUPD")
		aupdDecrypted, err = Store.ReadFile(aupdCachePath)
		if err != nil {
			return fmt.Errorf("could not read cached AUPD: %w", err)
		}
	} else {
		aupdImg, err := image.Read(bytes.NewReader(encrypted[0x5853000 : 0x5853000+0x12B603+0x800]))
		if err != nil {
			return fmt.Errorf("could not parse AUPD IMG1: %w", err)
		}
		aupdDecrypted, err = decrypt.Decrypt(app, aupdImg.Body, "")
		if err != nil {
			return fmt.Errorf("could not decrypt AUPD: %w", err)
		}
		if err := Store.WriteFile(aupdCachePath, aupdDecrypted); err != nil {
			return fmt.Errorf("could not cache AUPD: %w", err)
		}
	}

	// Place the decrypted bodies back. The IMG1 headers at these offsets are left intact -
	// verify_decrypt_img (patched out in the defanged AUPD EFI) handles both AES decryption
	// and signature checking, so bypassing it means the body is used as-is regardless of
	// the Format byte in the header.
	copy(encrypted[0x4E07000+0x800:], ososDecrypted)
	copy(encrypted[0x5853000+0x800:], aupdDecrypted)

	fspath := pathFor(&app.Desc.Kind, PayloadKindFirmwareDecrypted, "")
	if err := Store.WriteFile(fspath, encrypted); err != nil {
		return fmt.Errorf("could not write Firmware: %w", err)
	}
	return nil
}

func getFirmwareDefanged(app *app.App, options ...GetOption) ([]byte, error) {
	defanger, ok := cfw.FirmwareDefangers[app.Desc.Kind]
	if !ok {
		return nil, fmt.Errorf("don't know how to defang firmware for %s", app.Desc.Kind)
	}

	decrypted, err := Get(app, PayloadKindFirmwareDecrypted)
	if err != nil {
		return nil, err
	}
	defanged, err := defanger(decrypted)
	if err != nil {
		return nil, fmt.Errorf("defanging firmware failed: %w", err)
	}
	fspath := pathFor(&app.Desc.Kind, PayloadKindFirmwareDefanged, "")
	if err := Store.WriteFile(fspath, defanged); err != nil {
		slog.Warn("Could not write defanged firmware to disk", "err", err)
	}
	return defanged, nil
}

func getRetailOSCustomized(app *app.App, options ...GetOption) ([]byte, error) {
	decrypted, err := Get(app, PayloadKindRetailOSDecrypted)
	if err != nil {
		return nil, err
	}

	needle1 := []byte("Eject before disconnecting\x00")
	needle2 := []byte("freemyipod\x00")
	paddingLen := len(needle1) - len(needle2)
	needle2 = append(needle2, bytes.Repeat([]byte{0}, paddingLen)...)
	customized := bytes.ReplaceAll(decrypted, needle1, needle2)
	return customized, nil
}

func Get(app *app.App, payload PayloadKind, options ...GetOption) ([]byte, error) {
	// Defanged payloads are never cached - always rebuild from the decrypted source.
	switch payload {
	case PayloadKindWTFDefanged:
		return getWTFDefanged(app, options...)
	case PayloadKindRecoveryDefanged:
		return getRecoveryDefanged(app, options...)
	case PayloadKindFirmwareDefanged:
		return getFirmwareDefanged(app, options...)
	}

	url, err := urlForKind(payload, app.Desc.Kind)
	if err != nil {
		return nil, err
	}

	fspath := pathFor(&app.Desc.Kind, payload, url)
	if exists, err := Store.Exists(fspath); err == nil && exists {
		slog.Info("Get: Using cached data", "kind", app.Desc.Kind, "payload", payload, "path", fspath)
		return Store.ReadFile(fspath)
	}
	slog.Info("Get: No cached data, performing slow action...")

	switch payload {
	case PayloadKindWTFUpstream, PayloadKindRecoveryUpstream, PayloadKindFirmwareUpstream, PayloadKindBootloaderUpstream, PayloadKindRetailOSUpstream, PayloadKindDiagsUpstream:
		err = getPayloadFromPhobosIPSW(payload, app.Desc.Kind, url, options...)
	case PayloadKindBootloaderDecrypted:
		err = getBootloaderDecrypted(app, options...)
	case PayloadKindWTFDecrypted:
		err = getWTFDecrypted(app, options...)
	case PayloadKindDiagsDecrypted:
		err = getDiagsDecrypted(app, options...)
	case PayloadKindRetailOSDecrypted:
		err = getRetailOSDecrypted(app, options...)
	case PayloadKindRecoveryDecrypted:
		err = getRecoveryDecrypted(app, options...)
	case PayloadKindFirmwareDecrypted:
		err = getFirmwareDecrypted(app, options...)
	case PayloadKindRetailOSCustomized:
		return getRetailOSCustomized(app, options...)
	default:
		return nil, fmt.Errorf("don't know how to get a %s", payload)
	}
	if err != nil {
		return nil, err
	}

	return Store.ReadFile(fspath)
}

func pathFor(dev *devices.Kind, payload PayloadKind, upstreamURL string) string {
	devpart := "any"
	if dev != nil {
		devpart = string(*dev)
	}
	marker := ""
	if upstreamURL != "" {
		s := sha256.New()
		fmt.Fprintf(s, "%s", upstreamURL)
		marker = "-" + hex.EncodeToString(s.Sum(nil))
	}
	parts := []string{
		fmt.Sprintf("%s-%s%s.bin", devpart, payload, marker),
	}
	return path.Join(parts...)
}
