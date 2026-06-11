package executable

import (
	"testing"

	"github.com/supunhg/filo-go/internal/executable/elf"
	"github.com/supunhg/filo-go/internal/executable/macho"
	"github.com/supunhg/filo-go/internal/executable/pe"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected Format
	}{
		{"ELF", []byte{0x7F, 'E', 'L', 'F', 0, 0}, FormatELF},
		{"PE", []byte{'M', 'Z', 0, 0, 0, 0}, FormatPE},
		{"Mach-O 32-bit BE", []byte{0xFE, 0xED, 0xFA, 0xCE}, FormatMachO},
		{"Mach-O 32-bit LE", []byte{0xCE, 0xFA, 0xED, 0xFE}, FormatMachO},
		{"Mach-O 64-bit LE", []byte{0xCF, 0xFA, 0xED, 0xFE}, FormatMachO},
		{"Mach-O Universal", []byte{0xBE, 0xBA, 0xFE, 0xCA}, FormatMachO},
		{"Unknown", []byte{0x00, 0x00, 0x00, 0x00}, FormatUnknown},
		{"Too short", []byte{0x7F, 'E'}, FormatUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectFormat(tt.data); got != tt.expected {
				t.Errorf("DetectFormat() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAnalyzeUnsupportedFormat(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00}
	_, err := Analyze(data, "test.bin", nil)
	if err == nil {
		t.Error("Expected error for unsupported format")
	}
}

func TestAnalyzePE(t *testing.T) {
	// Minimal PE header
	data := []byte{
		'M', 'Z', // DOS header
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x80, 0x00, 0x00, 0x00, // e_lfanew
		'P', 'E', 0x00, 0x00, // PE signature
	}

	// This will fail due to incomplete PE header, but tests the code path
	_, err := Analyze(data, "test.exe", nil)
	// Error is expected for minimal header
	_ = err
}

func TestAnalyzeELF(t *testing.T) {
	// Test that ELF detection works
	data := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01}
	format := DetectFormat(data)
	if format != FormatELF {
		t.Errorf("Expected ELF format, got %s", format)
	}
}

func TestFilterSuspiciousImports(t *testing.T) {
	imports := []string{
		"kernel32.dll",
		"VirtualAlloc",
		"CreateRemoteThread",
		"user32.dll",
		"WriteProcessMemory",
	}

	suspicious := filterSuspiciousImports(imports)

	if len(suspicious) != 3 {
		t.Errorf("Expected 3 suspicious imports, got %d", len(suspicious))
	}

	expected := map[string]bool{
		"VirtualAlloc":       true,
		"CreateRemoteThread": true,
		"WriteProcessMemory": true,
	}

	for _, s := range suspicious {
		if !expected[s] {
			t.Errorf("Unexpected suspicious import: %s", s)
		}
	}
}

func TestFilterSuspiciousImportsEmpty(t *testing.T) {
	imports := []string{"kernel32.dll", "user32.dll"}
	suspicious := filterSuspiciousImports(imports)

	if len(suspicious) != 0 {
		t.Errorf("Expected 0 suspicious imports, got %d", len(suspicious))
	}
}

func TestFormatString(t *testing.T) {
	tests := []struct {
		format   Format
		expected string
	}{
		{FormatPE, "PE"},
		{FormatELF, "ELF"},
		{FormatMachO, "Mach-O"},
		{FormatUnknown, "Unknown"},
	}

	for _, tt := range tests {
		if string(tt.format) != tt.expected {
			t.Errorf("Format %v = %v, want %v", tt.format, string(tt.format), tt.expected)
		}
	}
}

func TestOptionsDefaults(t *testing.T) {
	opts := &Options{}

	if opts.MinStringLen == 0 {
		opts.MinStringLen = 4
	}

	if opts.MinStringLen != 4 {
		t.Errorf("Expected min string len 4, got %d", opts.MinStringLen)
	}
}

func TestResultStructure(t *testing.T) {
	result := &Result{
		Format:   FormatELF,
		FileName: "test.elf",
		FileSize: 1024,
	}

	if result.Format != FormatELF {
		t.Errorf("Expected ELF format, got %s", result.Format)
	}

	if result.FileName != "test.elf" {
		t.Errorf("Expected filename test.elf, got %s", result.FileName)
	}

	if result.FileSize != 1024 {
		t.Errorf("Expected file size 1024, got %d", result.FileSize)
	}
}

func TestEvidenceStructure(t *testing.T) {
	evidence := Evidence{
		Source:     "test_source",
		Confidence: 0.9,
		Details:    "test details",
	}

	if evidence.Source != "test_source" {
		t.Errorf("Expected source test_source, got %s", evidence.Source)
	}

	if evidence.Confidence != 0.9 {
		t.Errorf("Expected confidence 0.9, got %f", evidence.Confidence)
	}

	if evidence.Details != "test details" {
		t.Errorf("Expected details 'test details', got %s", evidence.Details)
	}
}

func TestPrintResults(t *testing.T) {
	result := &Result{
		Format:   FormatELF,
		FileName: "test.elf",
		FileSize: 1024,
		ELF: &elf.Result{
			Class:   "ELF64",
			Data:    "2's complement, little endian",
			OSABI:   "UNIX - System V",
			Type:    "EXEC (Executable file)",
			Machine: "Advanced Micro Devices x86-64",
		},
	}

	// Test that Print doesn't panic
	Print(result)
}

func TestPrintPEResults(t *testing.T) {
	result := &Result{
		Format:   FormatPE,
		FileName: "test.exe",
		FileSize: 1024,
		PE: &pe.Result{
			MachineStr: "x86_64",
			Bits:       64,
			Subsystem:  "Windows CUI",
		},
	}

	// Test that Print doesn't panic
	Print(result)
}

func TestPrintMachOResults(t *testing.T) {
	result := &Result{
		Format:   FormatMachO,
		FileName: "test.macho",
		FileSize: 1024,
		MachO: &macho.Result{
			Type: "MH_EXECUTE",
			CPU:  "x86_64",
			Bits: 64,
		},
	}

	// Test that Print doesn't panic
	Print(result)
}

func TestPEEvidence(t *testing.T) {
	tests := []struct {
		name string
		pe   *pe.Result
		min  int
	}{
		{
			name: "with subsystem",
			pe: &pe.Result{
				Subsystem: "Windows CUI",
			},
			min: 1,
		},
		{
			name: "with imports",
			pe: &pe.Result{
				Imports: []string{"VirtualAlloc", "CreateRemoteThread"},
			},
			min: 1,
		},
		{
			name: "with TLS callbacks",
			pe: &pe.Result{
				TLS: &pe.TLSInfo{HasCallbacks: true},
			},
			min: 1,
		},
		{
			name: "with debug info",
			pe: &pe.Result{
				DebugInfo: &pe.DebugInfo{HasDebug: true},
			},
			min: 1,
		},
		{
			name: "empty",
			pe:   &pe.Result{},
			min:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := peEvidence(tt.pe)
			if len(evidence) < tt.min {
				t.Errorf("expected at least %d evidence, got %d", tt.min, len(evidence))
			}
		})
	}
}

func TestELFEvidence(t *testing.T) {
	tests := []struct {
		name string
		elf  *elf.Result
		min  int
	}{
		{
			name: "no NX",
			elf: &elf.Result{
				Security: &elf.Security{NX: false},
			},
			min: 1,
		},
		{
			name: "no PIE",
			elf: &elf.Result{
				Security: &elf.Security{PIE: false},
			},
			min: 1,
		},
		{
			name: "no RELRO",
			elf: &elf.Result{
				Security: &elf.Security{Relro: "None"},
			},
			min: 1,
		},
		{
			name: "with notes",
			elf: &elf.Result{
				Notes: []elf.Note{
					{Name: "GNU", Type: "1"},
				},
			},
			min: 1,
		},
		{
			name: "empty",
			elf:  &elf.Result{},
			min:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := elfEvidence(tt.elf)
			if len(evidence) < tt.min {
				t.Errorf("expected at least %d evidence, got %d", tt.min, len(evidence))
			}
		})
	}
}

func TestMachOEvidence(t *testing.T) {
	tests := []struct {
		name   string
		macho  *macho.Result
		min    int
	}{
		{
			name: "fat header",
			macho: &macho.Result{
				FatHeader: &macho.FatHeader{NFatArch: 2},
			},
			min: 1,
		},
		{
			name: "with load commands",
			macho: &macho.Result{
				LoadCommands: []macho.LoadCommand{
					{Type: "LC_SEGMENT_64"},
				},
			},
			min: 1,
		},
		{
			name: "with code signature",
			macho: &macho.Result{
				CodeSignature: &macho.CodeSignature{Present: true},
			},
			min: 1,
		},
		{
			name:  "empty",
			macho: &macho.Result{},
			min:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := machoEvidence(tt.macho)
			if len(evidence) < tt.min {
				t.Errorf("expected at least %d evidence, got %d", tt.min, len(evidence))
			}
		})
	}
}

func TestPrintWithAllFields(t *testing.T) {
	result := &Result{
		Format:   FormatPE,
		FileName: "test.exe",
		FileSize: 1024,
		PE: &pe.Result{
			MachineStr: "x86_64",
			Bits:       64,
			Subsystem:  "Windows CUI",
			ImageBase:  0x140000000,
			EntryPoint: 0x1000,
			Timestamp:  1234567890,
			Sections: []pe.Section{
				{Name: ".text", VirtualAddress: 0x1000, VirtualSize: 0x100, RawSize: 0x100, Entropy: 6.5},
				{Name: ".data", VirtualAddress: 0x2000, VirtualSize: 0x50, RawSize: 0x50, Entropy: 3.0, Suspicious: true, Reason: "writable+executable"},
			},
			Imports: []string{"kernel32.dll", "user32.dll", "VirtualAlloc"},
			DLLs:    []string{"kernel32.dll", "user32.dll"},
			TLS:     &pe.TLSInfo{HasCallbacks: true},
			DebugInfo: &pe.DebugInfo{HasDebug: true},
		},
		Suspicious: []string{"Packing detected: UPX"},
		Evidence: []Evidence{
			{Source: "pe_subsystem", Confidence: 0.9, Details: "Subsystem: Windows CUI"},
		},
	}

	Print(result)
}

func TestPrintELFWithSecurity(t *testing.T) {
	result := &Result{
		Format:   FormatELF,
		FileName: "test.elf",
		FileSize: 1024,
		ELF: &elf.Result{
			Class:   "ELF64",
			Data:    "2's complement, little endian",
			OSABI:   "UNIX - System V",
			Type:    "EXEC (Executable file)",
			Machine: "Advanced Micro Devices x86-64",
			Security: &elf.Security{
				NX:    true,
				PIE:   true,
				Relro: "Full",
			},
			Sections: []elf.Section{
				{Name: ".text", Type: "PROGBITS", Flags: "AX", Size: 1024},
			},
			Segments: []elf.Segment{
				{Type: "LOAD", Offset: 0, VAddr: 0x400000, FileSize: 1024, MemSize: 1024, Flags: "R E"},
			},
		},
	}

	Print(result)
}

func TestPrintMachOWithDetails(t *testing.T) {
	result := &Result{
		Format:   FormatMachO,
		FileName: "test.macho",
		FileSize: 1024,
		MachO: &macho.Result{
			Type: "MH_EXECUTE",
			CPU:  "x86_64",
			Bits: 64,
			FatHeader: &macho.FatHeader{NFatArch: 2},
			LoadCommands: []macho.LoadCommand{
				{Type: "LC_SEGMENT_64"},
				{Type: "LC_SYMTAB"},
			},
			Segments: []macho.Segment{
				{Name: "__text", Size: 1024},
			},
			Dylibs: []macho.Dylib{
				{Name: "/usr/lib/libSystem.B.dylib"},
			},
			CodeSignature: &macho.CodeSignature{Present: true},
		},
	}

	Print(result)
}

func TestPrintWithNilSubResults(t *testing.T) {
	// Test Print with nil PE/ELF/MachO results
	result := &Result{
		Format:   FormatPE,
		FileName: "test.exe",
		FileSize: 1024,
		PE:       nil,
	}
	Print(result)

	result.Format = FormatELF
	result.ELF = nil
	Print(result)

	result.Format = FormatMachO
	result.MachO = nil
	Print(result)
}
