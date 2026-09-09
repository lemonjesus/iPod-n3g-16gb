package nand16gb

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// asmFS embeds the asm sources the patchers assemble and splice, so the
// package doesn't depend on a cwd-relative "asm/" path at runtime.
//
//go:embed asm/*.S
var asmFS embed.FS

// armCross is the binutils prefix for the as/ld/objcopy/nm chain below.
const armCross = "arm-linux-gnueabi-"

// runs an external toolchain command, including its output on failure
func runTool(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return nil
}

// defsyms is a builder for the --defsym pairs assembleLinkARM passes to `as`.
type defsyms []string

// Hex appends name=0x<val>, for addresses and bitmask-ish constants.
func (d defsyms) Hex(name string, val uint32) defsyms {
	return append(d, fmt.Sprintf("%s=0x%x", name, val))
}

// Int appends name=<val>, for plain counts/sizes.
func (d defsyms) Int(name string, val int) defsyms {
	return append(d, fmt.Sprintf("%s=%d", name, val))
}

// symtab maps assembler-visible symbol names to their linked addresses, as
// resolved via `nm` on the linked ELF: only lines with exactly 3
// whitespace-separated fields - "addr type name" - are symbol definitions.
type symtab map[string]uint32

func parseNM(output string) symtab {
	syms := symtab{}
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 3 {
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 32)
		if err != nil {
			continue
		}
		syms[fields[2]] = uint32(addr)
	}
	return syms
}

// assembleLinkARM assembles an embedded asm/<srcName> file with the given
// --defsym values, links it at loadVA (entry = loadVA), and extracts the raw
// binary + a symbol table via an as/ld/objcopy/nm chain.
func assembleLinkARM(workDir, srcName string, loadVA uint32, syms defsyms) ([]byte, symtab, error) {
	srcData, err := asmFS.ReadFile("asm/" + srcName)
	if err != nil {
		return nil, nil, fmt.Errorf("read embedded asm/%s: %w", srcName, err)
	}
	srcPath := filepath.Join(workDir, srcName)
	if err := os.WriteFile(srcPath, srcData, 0o644); err != nil {
		return nil, nil, err
	}

	base := strings.TrimSuffix(srcName, ".S")
	objFile := base + ".o"
	elfFile := base + ".elf"
	binFile := base + ".bin"

	var asArgs []string
	for _, d := range syms {
		asArgs = append(asArgs, "--defsym", d)
	}
	asArgs = append(asArgs, srcName, "-o", objFile)
	if err := runTool(workDir, armCross+"as", asArgs...); err != nil {
		return nil, nil, err
	}

	if err := runTool(workDir, armCross+"ld",
		fmt.Sprintf("-Ttext=0x%x", loadVA), "-e", fmt.Sprintf("0x%x", loadVA),
		objFile, "-o", elfFile); err != nil {
		return nil, nil, err
	}

	if err := runTool(workDir, armCross+"objcopy", "-O", "binary", elfFile, binFile); err != nil {
		return nil, nil, err
	}

	code, err := os.ReadFile(filepath.Join(workDir, binFile))
	if err != nil {
		return nil, nil, err
	}

	nmCmd := exec.Command(armCross+"nm", elfFile)
	nmCmd.Dir = workDir
	nmOut, err := nmCmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("%snm %s: %w", armCross, elfFile, err)
	}

	return code, parseNM(string(nmOut)), nil
}
