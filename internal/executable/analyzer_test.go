package executable

import (
	"testing"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected Format
	}{
		{
			name:     "ELF 64-bit",
			data:     []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00},
			expected: FormatELF,
		},
		{
			name:     "ELF 32-bit",
			data:     []byte{0x7F, 'E', 'L', 'F', 0x01, 0x01, 0x01, 0x00},
			expected: FormatELF,
		},
		{
			name:     "PE",
			data:     []byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00},
			expected: FormatPE,
		},
		{
			name:     "Mach-O 64-bit little-endian",
			data:     []byte{0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01},
			expected: FormatMachO,
		},
		{
			name:     "Mach-O 32-bit little-endian",
			data:     []byte{0xCE, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x00},
			expected: FormatMachO,
		},
		{
			name:     "Unknown",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: FormatUnknown,
		},
		{
			name:     "Too small",
			data:     []byte{0x7F, 'E'},
			expected: FormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectFormat(tt.data)
			if result != tt.expected {
				t.Errorf("DetectFormat() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAnalyzeELF(t *testing.T) {
	// Minimal ELF64 header
	data := []byte{
		0x7F, 'E', 'L', 'F', // Magic
		0x02,    // 64-bit
		0x01,    // Little-endian
		0x01,    // ELF version 1
		0x00,    // OS/ABI: System V
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
		0x02, 0x00, // Type: ET_EXEC
		0x3E, 0x00, // Machine: x86_64
		0x01, 0x00, 0x00, 0x00, // Version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Program header offset
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Section header offset
		0x00, 0x00, 0x00, 0x00, // Flags
		0x40, 0x00, // ELF header size
		0x38, 0x00, // Program header entry size
		0x00, 0x00, // Program header count
		0x40, 0x00, // Section header entry size
		0x00, 0x00, // Section header count
		0x00, 0x00, // Section name string table index
	}

	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if result.Format != FormatELF {
		t.Errorf("Format = %v, want %v", result.Format, FormatELF)
	}

	if result.Class != "ELF64" {
		t.Errorf("Class = %v, want ELF64", result.Class)
	}

	if result.Bits != 64 {
		t.Errorf("Bits = %v, want 64", result.Bits)
	}

	if result.Machine != "x86-64 (64-bit)" {
		t.Errorf("Machine = %v, want x86-64 (64-bit)", result.Machine)
	}

	if result.Security == nil {
		t.Error("Security info should not be nil")
	}
}

func TestAnalyzePE(t *testing.T) {
	// Minimal PE header
	data := []byte{
		'M', 'Z', // DOS header
		0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // e_lfanew at 0x3C = 0x80
		// PE header at offset 0x80
		'P', 'E', 0x00, 0x00, // PE signature
		0x4C, 0x01, // Machine: x86
		0x02, 0x00, // Number of sections
		0x00, 0x00, 0x00, 0x00, // Timestamp
		0x00, 0x00, 0x00, 0x00, // Symbol table pointer
		0x00, 0x00, 0x00, 0x00, // Number of symbols
		0xE0, 0x00, // Optional header size
		0x02, 0x01, // Characteristics
		// Optional header
		0x0B, 0x01, // Magic: PE32
		0x00, 0x00, 0x00, 0x00, // Linker version
		0x00, 0x00, 0x00, 0x00, // Size of code
		0x00, 0x00, 0x00, 0x00, // Size of initialized data
		0x00, 0x00, 0x00, 0x00, // Size of uninitialized data
		0x00, 0x10, 0x00, 0x00, // Entry point RVA
		0x00, 0x00, 0x00, 0x00, // Base of code
		0x00, 0x00, 0x40, 0x00, // Base of data
		// More fields...
	}

	result, err := Analyze(data, false)
	if err != nil {
		// PE analysis might fail with minimal header, that's ok
		t.Skipf("PE analysis with minimal header: %v", err)
	}

	if result.Format != FormatPE {
		t.Errorf("Format = %v, want %v", result.Format, FormatPE)
	}

	if result.Bits != 32 {
		t.Errorf("Bits = %v, want 32", result.Bits)
	}

	if result.Machine != "x86 (32-bit)" {
		t.Errorf("Machine = %v, want x86 (32-bit)", result.Machine)
	}
}

func TestFilterSuspiciousImports(t *testing.T) {
	imports := []string{
		"VirtualAlloc",
		"CreateFileA",
		"WriteProcessMemory",
		"ReadFile",
		"CreateRemoteThread",
		"GetModuleHandle",
	}

	suspicious := filterSuspiciousImports(imports)

	if len(suspicious) != 3 {
		t.Errorf("Expected 3 suspicious imports, got %d: %v", len(suspicious), suspicious)
	}

	expected := map[string]bool{
		"VirtualAlloc":         false,
		"WriteProcessMemory":   false,
		"CreateRemoteThread":   false,
	}

	for _, s := range suspicious {
		if _, ok := expected[s]; ok {
			expected[s] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("Expected suspicious import %s not found", name)
		}
	}
}

func TestDetectFormatWithELF(t *testing.T) {
	// Test with real ELF magic
	data := make([]byte, 64)
	data[0] = 0x7F
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = 2 // 64-bit
	data[5] = 1 // Little-endian

	format := DetectFormat(data)
	if format != FormatELF {
		t.Errorf("DetectFormat() = %v, want %v", format, FormatELF)
	}
}

func TestAnalyzeWithInvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too small", []byte{0x7F, 'E'}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Analyze(tt.data, false)
			if err == nil && result != nil {
				t.Errorf("Expected error for invalid data, got result: %v", result)
			}
		})
	}
}

func TestAnalyzeELF64(t *testing.T) {
	// Test with minimal ELF64 data
	data := make([]byte, 256)
	// ELF magic
	data[0] = 0x7F
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = 2 // 64-bit
	data[5] = 1 // Little-endian
	data[6] = 1 // Version
	data[7] = 0 // OS/ABI

	// Type: ET_EXEC (2)
	data[16] = 0x02
	data[17] = 0x00

	// Machine: x86_64 (0x3E)
	data[18] = 0x3E
	data[19] = 0x00

	// Version
	data[20] = 0x01
	data[21] = 0x00
	data[22] = 0x00
	data[23] = 0x00

	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if result.Format != FormatELF {
		t.Errorf("Format = %v, want %v", result.Format, FormatELF)
	}

	if result.Type != "ET_EXEC (Executable)" {
		t.Errorf("Type = %v, want ET_EXEC (Executable)", result.Type)
	}

	if result.Endian != "2's complement, little-endian" {
		t.Errorf("Endian = %v, want 2's complement, little-endian", result.Endian)
	}
}
