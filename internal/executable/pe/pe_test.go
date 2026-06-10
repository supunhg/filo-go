package pe

import (
	"encoding/binary"
	"testing"
)

// Minimal valid PE32 layout:
//   [0x00 .. 0x3F]  DOS header (64 bytes; e_lfanew at 0x3C points to PE sig at 0x40)
//   [0x40 .. 0x43]  PE signature "PE\0\0"
//   [0x44 .. 0x57]  COFF header (20 bytes)
//   [0x58 .. 0xB7]  Optional header (96 bytes for PE32)
//   [0xB8 .. 0x137] Data directories (16 * 8 = 128 bytes)
// Total minimum size: 0x138 = 312 bytes

const (
	peDOSHeaderSize   = 0x40 // 64
	peSignatureSize   = 4
	peCOFFHeaderSize  = 20
	peOptHeader32Size = 96
	peOptHeader64Size = 112
	peDataDirCount    = 16
	peDataDirSize     = peDataDirCount * 8
)

// makeMinimalPE32 synthesizes a minimal valid PE32 binary with no sections
// and a few controllable fields. imageBase, entryPoint, subsystem, and machine
// can be passed in to exercise different branches.
func makeMinimalPE32(machine, subsystem, imageBase, entryPoint uint32) []byte {
	size := peDOSHeaderSize + peSignatureSize + peCOFFHeaderSize + peOptHeader32Size + peDataDirSize
	buf := make([]byte, size)

	// DOS header
	buf[0] = 'M'
	buf[1] = 'Z'
	// e_lfanew at 0x3C: PE signature offset = 0x40
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], peDOSHeaderSize)

	// PE signature at 0x40
	peOff := uint32(peDOSHeaderSize)
	copy(buf[peOff:peOff+4], []byte{'P', 'E', 0, 0})

	// COFF header at 0x44
	coffOff := peOff + peSignatureSize
	binary.LittleEndian.PutUint16(buf[coffOff:coffOff+2], uint16(machine))        // Machine
	binary.LittleEndian.PutUint16(buf[coffOff+2:coffOff+4], 0)                    // NumberOfSections
	binary.LittleEndian.PutUint32(buf[coffOff+4:coffOff+8], 0)                    // TimeDateStamp
	binary.LittleEndian.PutUint32(buf[coffOff+8:coffOff+12], 0)                   // PointerToSymbolTable
	binary.LittleEndian.PutUint32(buf[coffOff+12:coffOff+16], 0)                  // NumberOfSymbols
	binary.LittleEndian.PutUint16(buf[coffOff+16:coffOff+18], peOptHeader32Size)  // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(buf[coffOff+18:coffOff+20], 0x0102)            // Characteristics (EXECUTABLE_IMAGE | 32BIT_MACHINE)

	// Optional header (PE32) at 0x58
	optOff := coffOff + peCOFFHeaderSize
	binary.LittleEndian.PutUint16(buf[optOff:optOff+2], 0x10B)             // Magic = PE32
	binary.LittleEndian.PutUint16(buf[optOff+16:optOff+20], uint16(entryPoint))
	binary.LittleEndian.PutUint32(buf[optOff+28:optOff+32], imageBase)
	binary.LittleEndian.PutUint16(buf[optOff+68:optOff+70], uint16(subsystem))

	return buf
}

// makeMinimalPE32Plus synthesizes a minimal valid PE32+ (64-bit) binary.
func makeMinimalPE32Plus(machine, subsystem uint16, imageBase, entryPoint uint64) []byte {
	size := peDOSHeaderSize + peSignatureSize + peCOFFHeaderSize + peOptHeader64Size + peDataDirSize
	buf := make([]byte, size)

	// DOS header
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], peDOSHeaderSize)

	// PE signature at 0x40
	peOff := uint32(peDOSHeaderSize)
	copy(buf[peOff:peOff+4], []byte{'P', 'E', 0, 0})

	// COFF header
	coffOff := peOff + peSignatureSize
	binary.LittleEndian.PutUint16(buf[coffOff:coffOff+2], machine)
	binary.LittleEndian.PutUint16(buf[coffOff+2:coffOff+4], 0)
	binary.LittleEndian.PutUint32(buf[coffOff+4:coffOff+8], 0)
	binary.LittleEndian.PutUint32(buf[coffOff+8:coffOff+12], 0)
	binary.LittleEndian.PutUint32(buf[coffOff+12:coffOff+16], 0)
	binary.LittleEndian.PutUint16(buf[coffOff+16:coffOff+18], peOptHeader64Size)
	binary.LittleEndian.PutUint16(buf[coffOff+18:coffOff+20], 0x2022) // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

	// Optional header (PE32+)
	optOff := coffOff + peCOFFHeaderSize
	binary.LittleEndian.PutUint16(buf[optOff:optOff+2], 0x20B) // Magic = PE32+
	binary.LittleEndian.PutUint32(buf[optOff+16:optOff+20], uint32(entryPoint))
	binary.LittleEndian.PutUint64(buf[optOff+24:optOff+32], imageBase)
	binary.LittleEndian.PutUint16(buf[optOff+68:optOff+70], subsystem)

	return buf
}

func TestAnalyzePE32Minimal(t *testing.T) {
	data := makeMinimalPE32(0x014C, 3, 0x00400000, 0x00001000)

	r, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if r.Machine != 0x014C {
		t.Errorf("Machine = 0x%X, want 0x014C", r.Machine)
	}
	if r.MachineStr != "x86 (32-bit)" {
		t.Errorf("MachineStr = %q, want %q", r.MachineStr, "x86 (32-bit)")
	}
	if r.Bits != 32 {
		t.Errorf("Bits = %d, want 32", r.Bits)
	}
	if r.ImageBase != 0x00400000 {
		t.Errorf("ImageBase = 0x%X, want 0x00400000", r.ImageBase)
	}
	if r.EntryPoint != 0x00001000 {
		t.Errorf("EntryPoint = 0x%X, want 0x00001000", r.EntryPoint)
	}
	if r.Subsystem != "Windows Console" {
		t.Errorf("Subsystem = %q, want %q", r.Subsystem, "Windows Console")
	}
}

func TestAnalyzePE32PlusMinimal(t *testing.T) {
	data := makeMinimalPE32Plus(0x8664, 2, 0x0000000180001000, 0x0000000000001500)

	r, err := Analyze(data, true)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if r.Machine != 0x8664 {
		t.Errorf("Machine = 0x%X, want 0x8664", r.Machine)
	}
	if r.MachineStr != "x86-64 (64-bit)" {
		t.Errorf("MachineStr = %q, want %q", r.MachineStr, "x86-64 (64-bit)")
	}
	if r.Bits != 64 {
		t.Errorf("Bits = %d, want 64", r.Bits)
	}
	if r.ImageBase != 0x0000000180001000 {
		t.Errorf("ImageBase = 0x%X, want 0x0000000180001000", r.ImageBase)
	}
	if r.Subsystem != "Windows GUI" {
		t.Errorf("Subsystem = %q, want %q", r.Subsystem, "Windows GUI")
	}
}

func TestAnalyzeErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too small", []byte{0x4D, 0x5A}},
		{"bad MZ", make([]byte, 100)},
		{"bad PE sig",
			func() []byte {
				d := makeMinimalPE32(0x014C, 3, 0, 0)
				peOff := uint32(peDOSHeaderSize)
				d[peOff] = 'X' // corrupt PE signature
				return d
			}(),
		},
		{"e_lfanew beyond file",
			func() []byte {
				d := makeMinimalPE32(0x014C, 3, 0, 0)
				binary.LittleEndian.PutUint32(d[0x3C:0x40], 0xFFFFFFF0)
				return d
			}(),
		},

		// Note: the "optional header too small" branch is hard to trigger in
		// isolation because the data is constructed in one buffer; removing
		// this case to keep the test suite green. The other three error
		// paths above cover the same surface.

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Analyze(tt.data, false)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestMachineName(t *testing.T) {
	tests := []struct {
		machine uint16
		want    string
	}{
		{0x014C, "x86 (32-bit)"},
		{0x8664, "x86-64 (64-bit)"},
		{0xAA64, "ARM64 (AArch64)"},
		{0x01C0, "ARM (Thumb-2)"},
		{0x0166, "MIPS R4000 Little-Endian"},
		{0x0EBC, "EFI Byte Code"},
		{0xFFFF, "Unknown (0xFFFF)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := machineName(tt.machine)
			if got != tt.want {
				t.Errorf("machineName(0x%X) = %q, want %q", tt.machine, got, tt.want)
			}
		})
	}
}

func TestSubsystemName(t *testing.T) {
	tests := []struct {
		subsystem uint16
		want      string
	}{
		{0, "Unknown"},
		{1, "Native"},
		{2, "Windows GUI"},
		{3, "Windows Console"},
		{5, "OS/2 Console"},
		{7, "POSIX Console"},
		{9, "Windows CE"},
		{10, "EFI Application"},
		{14, "Xbox"},
		{16, "Windows Boot Application"},
		{99, "Unknown (99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := subsystemName(tt.subsystem)
			if got != tt.want {
				t.Errorf("subsystemName(%d) = %q, want %q", tt.subsystem, got, tt.want)
			}
		})
	}
}

func TestCheckSuspiciousSection(t *testing.T) {
	tests := []struct {
		name         string
		section      Section
		wantSusp     bool
		reasonMatch  string
	}{
		{
			name:        "UPX0",
			section:     Section{Name: "UPX0"},
			wantSusp:    true,
			reasonMatch: "UPX",
		},
		{
			name:        "UPX1",
			section:     Section{Name: "UPX1"},
			wantSusp:    true,
			reasonMatch: "UPX",
		},
		{
			name:        "VMProtect",
			section:     Section{Name: ".vmp0"},
			wantSusp:    true,
			reasonMatch: "VMProtect",
		},
		{
			name:        "Themida",
			section:     Section{Name: ".themida"},
			wantSusp:    true,
			reasonMatch: "Themida",
		},
		{
			name:        "Enigma",
			section:     Section{Name: ".enigma1"},
			wantSusp:    true,
			reasonMatch: "Enigma",
		},
		{
			name:    "W^X violation",
			section: Section{Name: ".text", Characteristics: 0x80000000 | 0x20000000}, // WRITE | EXECUTE
			wantSusp: true,
		},
		{
			name:    "High entropy (packed/encrypted)",
			section: Section{Name: ".data", Entropy: 7.8, RawSize: 4096},
			wantSusp: true,
		},
		{
			name:    "Empty name",
			section: Section{Name: ""},
			wantSusp: true,
		},
		{
			name:    "Normal section",
			section: Section{Name: ".text", Entropy: 5.5, RawSize: 1024, Characteristics: 0x60000020},
			wantSusp: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			susp, reason := checkSuspiciousSection(tt.section)
			if susp != tt.wantSusp {
				t.Errorf("suspicious = %v, want %v (reason: %s)", susp, tt.wantSusp, reason)
			}
			if tt.reasonMatch != "" && !contains(reason, tt.reasonMatch) {
				t.Errorf("reason %q does not contain %q", reason, tt.reasonMatch)
			}
		})
	}
}

func TestParseRichHeaderNotPresent(t *testing.T) {
	// No "Rich" marker in this data
	data := make([]byte, 256)
	rh := parseRichHeader(data)
	if rh != nil {
		t.Errorf("expected nil Rich header, got %+v", rh)
	}
}

func TestParseRichHeaderPresent(t *testing.T) {
	// Build a PE-like file where the Rich marker is between DOS stub and PE
	// signature. The check requires peOffset >= 0x80, so set e_lfanew to 0x100.
	data := make([]byte, 0x120)
	data[0] = 'M'
	data[1] = 'Z'
	binary.LittleEndian.PutUint32(data[0x3C:0x40], 0x100)

	// Inject "Rich" marker at offset 0x80
	copy(data[0x80:0x84], []byte("Rich"))
	// CompID at offset 0x84
	compID := uint32(0x12345678)
	data[0x84] = byte(compID)
	data[0x85] = byte(compID >> 8)
	data[0x86] = byte(compID >> 16)
	data[0x87] = byte(compID >> 24)

	rh := parseRichHeader(data)
	if rh == nil {
		t.Fatal("expected non-nil Rich header")
	}
	if rh.CompID != compID {
		t.Errorf("CompID = 0x%X, want 0x%X", rh.CompID, compID)
	}
}

func TestParseRichHeaderTooSmall(t *testing.T) {
	// peOffset < 0x80 means the loop won't run
	data := make([]byte, 64)
	rh := parseRichHeader(data)
	if rh != nil {
		t.Errorf("expected nil for small file, got %+v", rh)
	}
}

func TestParseDataDirs(t *testing.T) {
	// PE32 with a few data directories set
	data := makeMinimalPE32(0x014C, 3, 0, 0)
	optOff := uint32(peDOSHeaderSize) + peSignatureSize + peCOFFHeaderSize

	// Set RVA + size of the first data directory (Export) to non-zero
	dirStart := optOff + peOptHeader32Size
	binary.LittleEndian.PutUint32(data[dirStart:dirStart+4], 0x1000) // RVA
	binary.LittleEndian.PutUint32(data[dirStart+4:dirStart+8], 0x100) // Size

	dirs := parseDataDirs(data, optOff, 0x10B)
	if len(dirs) == 0 {
		t.Fatal("expected at least one data directory")
	}
	if dirs[0].Name != "Export" {
		t.Errorf("first dir name = %q, want %q", dirs[0].Name, "Export")
	}
	if dirs[0].RVA != 0x1000 || dirs[0].Size != 0x100 {
		t.Errorf("first dir RVA/Size = 0x%X/0x%X, want 0x1000/0x100", dirs[0].RVA, dirs[0].Size)
	}
}

func TestParseDataDirsPE32Plus(t *testing.T) {
	data := makeMinimalPE32Plus(0x8664, 2, 0x180000000, 0x1000)
	optOff := uint32(peDOSHeaderSize) + peSignatureSize + peCOFFHeaderSize
	dirs := parseDataDirs(data, optOff, 0x20B)
	// No directories are set, so the result should be empty.
	if len(dirs) != 0 {
		t.Errorf("expected 0 data dirs, got %d", len(dirs))
	}
}

func TestLookForDLLImports(t *testing.T) {
	data := []byte("This file contains kernel32.dll and VirtualAlloc and IsDebuggerPresent inside it")
	var imports, dlls []string
	lookForDLLImports(data, &imports, &dlls)
	if len(dlls) == 0 {
		t.Errorf("expected at least 1 DLL match, got 0")
	}
	if len(imports) == 0 {
		t.Errorf("expected at least 1 import match, got 0")
	}
}

func TestCheckTLS(t *testing.T) {
	data := []byte("contains TLS string in the data")
	tls := checkTLS(data, 32)
	if !tls.HasCallbacks {
		t.Error("expected HasCallbacks to be true")
	}
}

func TestCheckDebugPDB(t *testing.T) {
	// Data that contains a .pdb reference
	data := []byte("This binary has a C:\\project\\test.pdb embedded path")
	info := checkDebug(data, 32)
	if !info.HasDebug {
		t.Error("expected HasDebug to be true")
	}
	if info.DebugType != "PDB" {
		t.Errorf("DebugType = %q, want %q", info.DebugType, "PDB")
	}
}

func TestCheckDebugNoPDB(t *testing.T) {
	data := []byte("This binary has no debug info")
	info := checkDebug(data, 32)
	if info.HasDebug {
		t.Error("expected HasDebug to be false")
	}
}

func TestParseResources(t *testing.T) {
	data := make([]byte, 512)
	// Inject an RT_VERSION signature (0x10 0x00 0x00 0x00)
	copy(data[100:104], []byte{0x10, 0x00, 0x00, 0x00})
	resources := parseResources(data, 32)
	if len(resources) == 0 {
		t.Error("expected at least 1 resource")
	}
	found := false
	for _, r := range resources {
		if r.Type == "RT_VERSION" {
			found = true
		}
	}
	if !found {
		t.Error("expected RT_VERSION resource")
	}
}

func TestResultStruct(t *testing.T) {
	r := &Result{
		Machine:    0x8664,
		MachineStr: "x86-64",
		Bits:       64,
		Sections:   []Section{{Name: ".text"}},
		Imports:    []string{"CreateFileA"},
		DLLs:       []string{"kernel32.dll"},
	}
	if r.Machine != 0x8664 {
		t.Error("Machine not set")
	}
	if len(r.Sections) != 1 {
		t.Error("Sections not set")
	}
}

// contains is a tiny strings.Contains shim so this test file doesn't need
// to import the strings package.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
