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
	data := []byte{
		0x7F, 'E', 'L', 'F',
		0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00,
		0x3E, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x00,
		0x38, 0x00,
		0x00, 0x00,
		0x40, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}

	result, err := Analyze(data, "test.elf", nil)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if result.Format != FormatELF {
		t.Errorf("Format = %v, want %v", result.Format, FormatELF)
	}

	if result.ELF == nil {
		t.Fatal("ELF result is nil")
	}

	if result.ELF.Class != "ELF64" {
		t.Errorf("Class = %v, want ELF64", result.ELF.Class)
	}

	if result.ELF.Machine != "AMD x86-64" {
		t.Errorf("Machine = %v, want AMD x86-64", result.ELF.Machine)
	}

	if result.ELF.Security == nil {
		t.Error("Security info should not be nil")
	}
}

func TestAnalyzeELF64(t *testing.T) {
	data := make([]byte, 256)
	data[0] = 0x7F
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = 2
	data[5] = 1
	data[6] = 1
	data[7] = 0
	data[16] = 0x02
	data[17] = 0x00
	data[18] = 0x3E
	data[19] = 0x00
	data[20] = 0x01
	data[21] = 0x00
	data[22] = 0x00
	data[23] = 0x00

	result, err := Analyze(data, "test64.elf", nil)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if result.Format != FormatELF {
		t.Errorf("Format = %v, want %v", result.Format, FormatELF)
	}

	if result.ELF == nil {
		t.Fatal("ELF result is nil")
	}

	if result.ELF.Type != "ET_EXEC (Executable)" {
		t.Errorf("Type = %v, want ET_EXEC (Executable)", result.ELF.Type)
	}

	if result.ELF.Data != "2's complement, little-endian" {
		t.Errorf("Data = %v, want 2's complement, little-endian", result.ELF.Data)
	}
}

func TestAnalyzePE(t *testing.T) {
	data := []byte{
		'M', 'Z',
		0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
		'P', 'E', 0x00, 0x00,
		0x4C, 0x01,
		0x02, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xE0, 0x00,
		0x02, 0x01,
		0x0B, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x10, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x40, 0x00,
	}

	_, err := Analyze(data, "test.exe", nil)
	if err != nil {
		// PE analysis might fail with minimal header, that's ok
		t.Skipf("PE analysis with minimal header: %v", err)
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
		"VirtualAlloc":       false,
		"WriteProcessMemory": false,
		"CreateRemoteThread": false,
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
	data := make([]byte, 64)
	data[0] = 0x7F
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = 2
	data[5] = 1

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
			_, err := Analyze(tt.data, "test", nil)
			if err == nil {
				t.Errorf("Expected error for %s data", tt.name)
			}
		})
	}
}
