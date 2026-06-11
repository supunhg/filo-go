package executable

import (
	"fmt"
	"strings"

	"github.com/supunhg/filo-go/internal/executable/elf"
	"github.com/supunhg/filo-go/internal/executable/macho"
	"github.com/supunhg/filo-go/internal/executable/packing"
	"github.com/supunhg/filo-go/internal/executable/pe"
)

// Format represents the executable format type.
type Format string

const (
	FormatPE      Format = "PE"
	FormatELF     Format = "ELF"
	FormatMachO   Format = "Mach-O"
	FormatUnknown Format = "Unknown"
)

// Result holds the complete executable analysis output.
type Result struct {
	Format     Format          `json:"format"`
	FileName   string          `json:"file_name"`
	FileSize   int64           `json:"file_size"`
	SHA256     string          `json:"sha256"`
	PE         *pe.Result      `json:"pe,omitempty"`
	ELF        *elf.Result     `json:"elf,omitempty"`
	MachO      *macho.Result   `json:"macho,omitempty"`
	Packing    *packing.Result `json:"packing,omitempty"`
	Suspicious []string        `json:"suspicious,omitempty"`
	Evidence   []Evidence      `json:"evidence,omitempty"`
}

// Evidence represents a single detection signal.
type Evidence struct {
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	Details    string  `json:"details"`
}

// Options controls analysis behavior.
type Options struct {
	DeepScan       bool
	ExtractStrings bool
	MinStringLen   int
}

// DetectFormat identifies the executable format from magic bytes.
func DetectFormat(data []byte) Format {
	if len(data) < 4 {
		return FormatUnknown
	}

	// ELF
	if data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return FormatELF
	}

	// PE (MZ header)
	if data[0] == 'M' && data[1] == 'Z' {
		return FormatPE
	}

	// Mach-O (32-bit and 64-bit, big and little endian)
	if (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA) ||
		(data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED) ||
		(data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED) ||
		(data[0] == 0xBE && data[1] == 0xBA && data[2] == 0xFE) {
		return FormatMachO
	}

	return FormatUnknown
}

// Analyze performs deep analysis on executable data.
func Analyze(data []byte, filePath string, opts *Options) (*Result, error) {
	if opts == nil {
		opts = &Options{MinStringLen: 4}
	}

	format := DetectFormat(data)
	result := &Result{
		Format:   format,
		FileName: filePath,
		FileSize: int64(len(data)),
	}

	switch format {
	case FormatPE:
		peResult, err := pe.Analyze(data, opts.DeepScan)
		if err != nil {
			return nil, fmt.Errorf("PE analysis failed: %w", err)
		}
		result.PE = peResult
		result.Evidence = append(result.Evidence, peEvidence(peResult)...)

	case FormatELF:
		elfResult, err := elf.Analyze(data, opts.DeepScan)
		if err != nil {
			return nil, fmt.Errorf("ELF analysis failed: %w", err)
		}
		result.ELF = elfResult
		result.Evidence = append(result.Evidence, elfEvidence(elfResult)...)

	case FormatMachO:
		machoResult, err := macho.Analyze(data, opts.DeepScan)
		if err != nil {
			return nil, fmt.Errorf("Mach-O analysis failed: %w", err)
		}
		result.MachO = machoResult
		result.Evidence = append(result.Evidence, machoEvidence(machoResult)...)

	default:
		return nil, fmt.Errorf("unsupported executable format")
	}

	// Packing detection
	packingResult := packing.Detect(data, string(format))
	result.Packing = packingResult
	if packingResult.Detected {
		result.Suspicious = append(result.Suspicious,
			fmt.Sprintf("Packing detected: %s (confidence: %.0f%%)",
				packingResult.Packer, packingResult.Confidence*100))
	}

	return result, nil
}

// peEvidence extracts evidence from PE analysis.
func peEvidence(r *pe.Result) []Evidence {
	var evidence []Evidence

	if r.Subsystem != "" {
		evidence = append(evidence, Evidence{
			Source:     "pe_subsystem",
			Confidence: 0.9,
			Details:    fmt.Sprintf("Subsystem: %s", r.Subsystem),
		})
	}

	if len(r.Imports) > 0 {
		suspiciousImports := filterSuspiciousImports(r.Imports)
		if len(suspiciousImports) > 0 {
			evidence = append(evidence, Evidence{
				Source:     "pe_suspicious_imports",
				Confidence: 0.7,
				Details:    fmt.Sprintf("Suspicious imports: %s", strings.Join(suspiciousImports, ", ")),
			})
		}
	}

	if r.TLS != nil && r.TLS.HasCallbacks {
		evidence = append(evidence, Evidence{
			Source:     "pe_tls_callbacks",
			Confidence: 0.8,
			Details:    "TLS callbacks detected (common in malware)",
		})
	}

	if r.DebugInfo != nil && r.DebugInfo.HasDebug {
		evidence = append(evidence, Evidence{
			Source:     "pe_debug_info",
			Confidence: 0.5,
			Details:    "Debug information present",
		})
	}

	return evidence
}

// elfEvidence extracts evidence from ELF analysis.
func elfEvidence(r *elf.Result) []Evidence {
	var evidence []Evidence

	if r.Security != nil {
		if !r.Security.NX {
			evidence = append(evidence, Evidence{
				Source:     "elf_security",
				Confidence: 0.8,
				Details:    "NX (non-executable) bit not set - stack is executable",
			})
		}
		if !r.Security.PIE {
			evidence = append(evidence, Evidence{
				Source:     "elf_security",
				Confidence: 0.7,
				Details:    "PIE not enabled - ASLR less effective",
			})
		}
		if r.Security.Relro == "None" {
			evidence = append(evidence, Evidence{
				Source:     "elf_security",
				Confidence: 0.6,
				Details:    "No RELRO - GOT writable",
			})
		}
	}

	if len(r.Notes) > 0 {
		evidence = append(evidence, Evidence{
			Source:     "elf_notes",
			Confidence: 0.5,
			Details:    fmt.Sprintf("Found %d ELF notes", len(r.Notes)),
		})
	}

	return evidence
}

// machoEvidence extracts evidence from Mach-O analysis.
func machoEvidence(r *macho.Result) []Evidence {
	var evidence []Evidence

	if r.FatHeader != nil {
		evidence = append(evidence, Evidence{
			Source:     "macho_fat",
			Confidence: 0.9,
			Details:    fmt.Sprintf("Universal binary with %d architectures", r.FatHeader.NFatArch),
		})
	}

	if len(r.LoadCommands) > 0 {
		evidence = append(evidence, Evidence{
			Source:     "macho_load_commands",
			Confidence: 0.5,
			Details:    fmt.Sprintf("Found %d load commands", len(r.LoadCommands)),
		})
	}

	if r.CodeSignature != nil && r.CodeSignature.Present {
		evidence = append(evidence, Evidence{
			Source:     "macho_codesign",
			Confidence: 0.9,
			Details:    "Code signature present",
		})
	}

	return evidence
}

// filterSuspiciousImports identifies potentially malicious imports.
func filterSuspiciousImports(imports []string) []string {
	suspicious := []string{
		"VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
		"CreateRemoteThread", "NtUnmapViewOfSection", "SetWindowsHookEx",
		"EnumProcesses", "OpenProcess", "ReadProcessMemory",
		"WinExec", "ShellExecute", "CreateProcess",
		"InternetOpen", "InternetConnect", "HttpOpenRequest",
		"URLDownloadToFile", "WinHttpOpen",
		"RegSetValueEx", "RegCreateKeyEx",
		"CreateService", "StartService",
		"AdjustTokenPrivileges", "LookupPrivilegeValue",
		"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
		"NtQueryInformationProcess", "OutputDebugString",
	}

	var found []string
	importSet := make(map[string]bool)
	for _, imp := range imports {
		importSet[imp] = true
	}

	for _, sus := range suspicious {
		if importSet[sus] {
			found = append(found, sus)
		}
	}

	return found
}

// Print displays executable analysis results.
func Print(r *Result) {
	fmt.Println()
	fmt.Printf("  Executable Analysis: %s\n", r.FileName)
	fmt.Printf("  Format: %s\n", r.Format)
	fmt.Printf("  File Size: %d bytes\n", r.FileSize)
	fmt.Println()

	switch r.Format {
	case FormatPE:
		if r.PE != nil {
			printPE(r.PE)
		}
	case FormatELF:
		if r.ELF != nil {
			printELF(r.ELF)
		}
	case FormatMachO:
		if r.MachO != nil {
			printMachO(r.MachO)
		}
	}

	if r.Packing != nil && r.Packing.Detected {
		fmt.Println("  ⚠  Packing Detected:")
		fmt.Printf("    Packer: %s\n", r.Packing.Packer)
		fmt.Printf("    Confidence: %.0f%%\n", r.Packing.Confidence*100)
		if len(r.Packing.Signatures) > 0 {
			fmt.Println("    Signatures:")
			for _, sig := range r.Packing.Signatures {
				fmt.Printf("      • %s\n", sig)
			}
		}
		fmt.Println()
	}

	if len(r.Suspicious) > 0 {
		fmt.Println("  ⚠  Suspicious Indicators:")
		for _, s := range r.Suspicious {
			fmt.Printf("    • %s\n", s)
		}
		fmt.Println()
	}

	if len(r.Evidence) > 0 {
		fmt.Println("  Evidence:")
		for _, e := range r.Evidence {
			fmt.Printf("    [%s] (confidence: %.0f%%) %s\n",
				e.Source, e.Confidence*100, e.Details)
		}
		fmt.Println()
	}
}

func printPE(r *pe.Result) {
	fmt.Println("  PE Analysis:")
	fmt.Printf("    Machine: %s\n", r.MachineStr)
	fmt.Printf("    Bits: %d\n", r.Bits)
	fmt.Printf("    Subsystem: %s\n", r.Subsystem)
	fmt.Printf("    Image Base: 0x%X\n", r.ImageBase)
	fmt.Printf("    Entry Point: 0x%X\n", r.EntryPoint)
	fmt.Printf("    Sections: %d\n", len(r.Sections))
	fmt.Printf("    Timestamp: %d\n", r.Timestamp)

	if len(r.Sections) > 0 {
		fmt.Println("    Sections:")
		for _, sec := range r.Sections {
			fmt.Printf("      %-8s  VirtAddr: 0x%08X  VirtSize: 0x%08X  RawSize: 0x%08X  Entropy: %.2f\n",
				sec.Name, sec.VirtualAddress, sec.VirtualSize, sec.RawSize, sec.Entropy)
			if sec.Suspicious {
				fmt.Printf("        ⚠  Suspicious: %s\n", sec.Reason)
			}
		}
	}

	if len(r.Imports) > 0 {
		fmt.Printf("    Imports (%d):\n", len(r.Imports))
		for i, imp := range r.Imports {
			if i >= 20 {
				fmt.Printf("      ... and %d more\n", len(r.Imports)-20)
				break
			}
			fmt.Printf("      %s\n", imp)
		}
	}

	if len(r.DLLs) > 0 {
		fmt.Printf("    DLLs (%d):\n", len(r.DLLs))
		for _, dll := range r.DLLs {
			fmt.Printf("      %s\n", dll)
		}
	}

	if r.TLS != nil && r.TLS.HasCallbacks {
		fmt.Println("    TLS: Has callbacks")
	}

	if r.DebugInfo != nil && r.DebugInfo.HasDebug {
		fmt.Println("    Debug: Present")
	}

	if len(r.Resources) > 0 {
		fmt.Printf("    Resources: %d\n", len(r.Resources))
	}

	fmt.Println()
}

func printELF(r *elf.Result) {
	fmt.Println("  ELF Analysis:")
	fmt.Printf("    Class: %s\n", r.Class)
	fmt.Printf("    Data: %s\n", r.Data)
	fmt.Printf("    OS/ABI: %s\n", r.OSABI)
	fmt.Printf("    Type: %s\n", r.Type)
	fmt.Printf("    Machine: %s\n", r.Machine)
	fmt.Printf("    Entry Point: 0x%X\n", r.EntryPoint)
	fmt.Printf("    Sections: %d\n", len(r.Sections))
	fmt.Printf("    Segments: %d\n", len(r.Segments))

	if len(r.Sections) > 0 {
		fmt.Println("    Sections:")
		for _, sec := range r.Sections {
			fmt.Printf("      %-16s  Addr: 0x%016X  Size: 0x%08X  Flags: %s  Entropy: %.2f\n",
				sec.Name, sec.Address, sec.Size, sec.Flags, sec.Entropy)
		}
	}

	if r.Security != nil {
		fmt.Println("    Security:")
		fmt.Printf("      NX: %v\n", r.Security.NX)
		fmt.Printf("      PIE: %v\n", r.Security.PIE)
		fmt.Printf("      RELRO: %s\n", r.Security.Relro)
		fmt.Printf("      Stack Canary: %v\n", r.Security.StackCanary)
		fmt.Printf("      FORTIFY: %v\n", r.Security.Fortify)
	}

	if len(r.Notes) > 0 {
		fmt.Printf("    Notes: %d\n", len(r.Notes))
		for _, note := range r.Notes {
			fmt.Printf("      [%s] %s\n", note.Type, note.Name)
		}
	}

	if len(r.DynamicDeps) > 0 {
		fmt.Printf("    Dynamic Dependencies (%d):\n", len(r.DynamicDeps))
		for _, dep := range r.DynamicDeps {
			fmt.Printf("      %s\n", dep)
		}
	}

	if r.Symbols != nil {
		fmt.Printf("    Symbols: %d imported\n", len(r.Symbols.Imports))
	}

	fmt.Println()
}

func printMachO(r *macho.Result) {
	fmt.Println("  Mach-O Analysis:")
	fmt.Printf("    Type: %s\n", r.Type)
	fmt.Printf("    CPU: %s\n", r.CPU)
	fmt.Printf("    Bits: %d\n", r.Bits)
	fmt.Printf("    Endian: %s\n", r.Endian)

	if r.FatHeader != nil {
		fmt.Printf("    Universal: Yes (%d architectures)\n", r.FatHeader.NFatArch)
		for _, arch := range r.FatHeader.Arches {
			fmt.Printf("      - %s (offset: 0x%X, size: 0x%X)\n",
				arch.CPU, arch.Offset, arch.Size)
		}
	}

	if len(r.LoadCommands) > 0 {
		fmt.Printf("    Load Commands: %d\n", len(r.LoadCommands))
		for i, cmd := range r.LoadCommands {
			if i >= 15 {
				fmt.Printf("      ... and %d more\n", len(r.LoadCommands)-15)
				break
			}
			fmt.Printf("      %s (size: %d)\n", cmd.Type, cmd.Size)
		}
	}

	if len(r.Segments) > 0 {
		fmt.Printf("    Segments: %d\n", len(r.Segments))
		for _, seg := range r.Segments {
			fmt.Printf("      %-16s  Addr: 0x%016X  Size: 0x%08X  MaxProt: %s  InitProt: %s\n",
				seg.Name, seg.Address, seg.Size, seg.MaxProt, seg.InitProt)
		}
	}

	if r.CodeSignature != nil && r.CodeSignature.Present {
		fmt.Printf("    Code Signature: Present (size: %d)\n", r.CodeSignature.Size)
	}

	if len(r.Dylibs) > 0 {
		fmt.Printf("    Dynamic Libraries (%d):\n", len(r.Dylibs))
		for _, dylib := range r.Dylibs {
			fmt.Printf("      %s (compat: %s, current: %s)\n",
				dylib.Name, dylib.CompatVersion, dylib.CurrentVersion)
		}
	}

	fmt.Println()
}
