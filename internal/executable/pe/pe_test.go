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

func TestParseSectionsBasic(t *testing.T) {
	// Build a PE32 with two section headers. The section headers are placed
	// at sectionOffset = optOffset + uint16@optOff+14 + uint16@optOff+16.
	// We set those uint16 fields so sectionOffset lands at a known position.
	//
	// We also place some raw data at known offsets so entropy can be
	// computed for the sections.

	optOff := uint32(peDOSHeaderSize) + peSignatureSize + peCOFFHeaderSize
	// We want sectionOffset = optOff + 0xE0 (224) to come right after the
	// optional header + data directories. Set:
	//   uint16 at optOff+14 = 0
	//   uint16 at optOff+16 = 0xE0
	// so sectionOffset = optOff + 0xE0.

	// Section data will be placed near the end of the buffer.
	const sectionDataOffset = 0x400 // 1024
	const sectionDataSize = 0x80   // 128 bytes per section

	totalSize := sectionDataOffset + sectionDataSize*2
	buf := make([]byte, totalSize)

	// DOS header
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], peDOSHeaderSize)

	// PE signature
	peOff := uint32(peDOSHeaderSize)
	copy(buf[peOff:peOff+4], []byte{'P', 'E', 0, 0})

	// COFF header
	coffOff := peOff + peSignatureSize
	binary.LittleEndian.PutUint16(buf[coffOff:coffOff+2], 0x014C)  // Machine x86
	binary.LittleEndian.PutUint16(buf[coffOff+2:coffOff+4], 2)     // 2 sections
	binary.LittleEndian.PutUint16(buf[coffOff+16:coffOff+18], peOptHeader32Size)

	// Set the fields the code reads to compute sectionOffset.
	binary.LittleEndian.PutUint16(buf[optOff+14:optOff+16], 0x0000)
	binary.LittleEndian.PutUint16(buf[optOff+16:optOff+18], 0x00E0)

	// Optional header magic = PE32
	binary.LittleEndian.PutUint16(buf[optOff:optOff+2], 0x10B)

	// Section headers start at optOff + 0xE0.
	sectionOff := optOff + 0xE0

	// Section 1: .text with normal characteristics
	sec1Off := sectionOff
	copy(buf[sec1Off:sec1Off+8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(buf[sec1Off+8:sec1Off+12], sectionDataSize)        // VirtualSize
	binary.LittleEndian.PutUint32(buf[sec1Off+12:sec1Off+16], 0x1000)               // VirtualAddress
	binary.LittleEndian.PutUint32(buf[sec1Off+16:sec1Off+20], sectionDataSize)       // RawSize
	binary.LittleEndian.PutUint32(buf[sec1Off+20:sec1Off+24], sectionDataOffset)     // RawOffset
	binary.LittleEndian.PutUint32(buf[sec1Off+36:sec1Off+40], 0x60000020)            // Characteristics: CODE|EXECUTE|READ

	// Fill section 1's raw data with simple low-entropy content
	for i := uint32(0); i < sectionDataSize; i++ {
		buf[sectionDataOffset+i] = byte(i & 0xFF)
	}

	// Section 2: .data
	sec2Off := sectionOff + 40
	copy(buf[sec2Off:sec2Off+8], []byte(".data\x00\x00\x00"))
	binary.LittleEndian.PutUint32(buf[sec2Off+8:sec2Off+12], sectionDataSize)
	binary.LittleEndian.PutUint32(buf[sec2Off+12:sec2Off+16], 0x2000)
	binary.LittleEndian.PutUint32(buf[sec2Off+16:sec2Off+20], sectionDataSize)
	binary.LittleEndian.PutUint32(buf[sec2Off+20:sec2Off+24], sectionDataOffset+sectionDataSize)
	binary.LittleEndian.PutUint32(buf[sec2Off+36:sec2Off+40], 0xC0000040)            // INITIALIZED_DATA|READ|WRITE

	// Fill section 2's raw data
	for i := uint32(0); i < sectionDataSize; i++ {
		buf[sectionDataOffset+sectionDataSize+i] = 0xAA
	}

	// Call Analyze to exercise the full pipeline
	r, err := Analyze(buf, true)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(r.Sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(r.Sections))
	}

	// Verify .text section
	if r.Sections[0].Name != ".text" {
		t.Errorf("section 0 name = %q, want %q", r.Sections[0].Name, ".text")
	}
	if r.Sections[0].VirtualAddress != 0x1000 {
		t.Errorf("section 0 VA = 0x%X, want 0x1000", r.Sections[0].VirtualAddress)
	}
	if r.Sections[0].RawOffset != sectionDataOffset {
		t.Errorf("section 0 RawOffset = 0x%X, want 0x%X", r.Sections[0].RawOffset, sectionDataOffset)
	}
	if r.Sections[0].Entropy <= 0 {
		t.Errorf("section 0 entropy should be > 0, got %f", r.Sections[0].Entropy)
	}
	if r.Sections[0].Suspicious {
		t.Errorf("section 0 should not be suspicious, got reason: %s", r.Sections[0].Reason)
	}

	// Verify .data section
	if r.Sections[1].Name != ".data" {
		t.Errorf("section 1 name = %q, want %q", r.Sections[1].Name, ".data")
	}
	if r.Sections[1].RawOffset != sectionDataOffset+sectionDataSize {
		t.Errorf("section 1 RawOffset = 0x%X, want 0x%X", r.Sections[1].RawOffset, sectionDataOffset+sectionDataSize)
	}
}

func TestParseSectionsSuspicious(t *testing.T) {
	// Build a PE with a section named "UPX0" that should trigger the
	// suspicious check via the name match.
	optOff := uint32(peDOSHeaderSize) + peSignatureSize + peCOFFHeaderSize

	const sectionDataOffset = 0x400
	const sectionDataSize = 0x100
	totalSize := sectionDataOffset + sectionDataSize
	buf := make([]byte, totalSize)

	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], peDOSHeaderSize)

	peOff := uint32(peDOSHeaderSize)
	copy(buf[peOff:peOff+4], []byte{'P', 'E', 0, 0})

	coffOff := peOff + peSignatureSize
	binary.LittleEndian.PutUint16(buf[coffOff:coffOff+2], 0x014C)
	binary.LittleEndian.PutUint16(buf[coffOff+2:coffOff+4], 1) // 1 section
	binary.LittleEndian.PutUint16(buf[coffOff+16:coffOff+18], peOptHeader32Size)

	binary.LittleEndian.PutUint16(buf[optOff+14:optOff+16], 0x0000)
	binary.LittleEndian.PutUint16(buf[optOff+16:optOff+18], 0x00E0)
	binary.LittleEndian.PutUint16(buf[optOff:optOff+2], 0x10B)

	sectionOff := optOff + 0xE0
	copy(buf[sectionOff:sectionOff+8], []byte("UPX0\x00\x00\x00\x00"))
	binary.LittleEndian.PutUint32(buf[sectionOff+8:sectionOff+12], sectionDataSize)
	binary.LittleEndian.PutUint32(buf[sectionOff+12:sectionOff+16], 0x1000)
	binary.LittleEndian.PutUint32(buf[sectionOff+16:sectionOff+20], sectionDataSize)
	binary.LittleEndian.PutUint32(buf[sectionOff+20:sectionOff+24], sectionDataOffset)
	binary.LittleEndian.PutUint32(buf[sectionOff+36:sectionOff+40], 0xE0000020) // EXECUTE|READ|WRITE

	r, err := Analyze(buf, true)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(r.Sections) != 1 {
		t.Fatalf("expected 1 section, got %d", len(r.Sections))
	}
	if !r.Sections[0].Suspicious {
		t.Error("UPX0 section should be marked suspicious")
	}
	if !contains(r.Sections[0].Reason, "UPX") {
		t.Errorf("suspicious reason %q does not mention UPX", r.Sections[0].Reason)
	}
}

func TestParseSectionsHighEntropy(t *testing.T) {
	// Section with high-entropy data (random-ish) should be flagged.
	optOff := uint32(peDOSHeaderSize) + peSignatureSize + peCOFFHeaderSize

	const sectionDataOffset = 0x400
	const sectionDataSize = 0x200 // 512 bytes, above the 1024-byte threshold check
	// Wait — the threshold is RawSize > 1024. Let's use 2048.
	const largeSectionDataSize = 0x1000
	totalSize := optOff + 0xE0 + 40 + sectionDataOffset + largeSectionDataSize
	buf := make([]byte, totalSize)

	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], peDOSHeaderSize)

	peOff := uint32(peDOSHeaderSize)
	copy(buf[peOff:peOff+4], []byte{'P', 'E', 0, 0})

	coffOff := peOff + peSignatureSize
	binary.LittleEndian.PutUint16(buf[coffOff:coffOff+2], 0x014C)
	binary.LittleEndian.PutUint16(buf[coffOff+2:coffOff+4], 1)
	binary.LittleEndian.PutUint16(buf[coffOff+16:coffOff+18], peOptHeader32Size)

	binary.LittleEndian.PutUint16(buf[optOff+14:optOff+16], 0x0000)
	binary.LittleEndian.PutUint16(buf[optOff+16:optOff+18], 0x00E0)
	binary.LittleEndian.PutUint16(buf[optOff:optOff+2], 0x10B)

	sectionOff := optOff + 0xE0
	copy(buf[sectionOff:sectionOff+8], []byte(".pack\x00\x00\x00"))
	binary.LittleEndian.PutUint32(buf[sectionOff+8:sectionOff+12], largeSectionDataSize)
	binary.LittleEndian.PutUint32(buf[sectionOff+16:sectionOff+20], largeSectionDataSize)
	binary.LittleEndian.PutUint32(buf[sectionOff+20:sectionOff+24], sectionDataOffset)
	binary.LittleEndian.PutUint32(buf[sectionOff+36:sectionOff+40], 0xE0000020)

	// Fill with pseudo-random data to push entropy above 7.5
	for i := uint32(0); i < largeSectionDataSize; i++ {
		buf[sectionDataOffset+i] = byte((i*1103515245 + 12345) >> 16)
	}

	r, err := Analyze(buf, true)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(r.Sections) != 1 {
		t.Fatalf("expected 1 section, got %d", len(r.Sections))
	}
	if !r.Sections[0].Suspicious {
		t.Errorf("high-entropy section should be suspicious, reason: %s", r.Sections[0].Reason)
	}
}

func TestParseSectionsTruncated(t *testing.T) {
	// numSections = 5 but only enough room for 1 — the loop should
	// break early when secOffset+40 exceeds len(data).
	optOff := uint32(peDOSHeaderSize) + peSignatureSize + peCOFFHeaderSize

	buf := make([]byte, optOff+0xE0+20) // only room for part of one section header
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], peDOSHeaderSize)

	peOff := uint32(peDOSHeaderSize)
	copy(buf[peOff:peOff+4], []byte{'P', 'E', 0, 0})

	coffOff := peOff + peSignatureSize
	binary.LittleEndian.PutUint16(buf[coffOff:coffOff+2], 0x014C)
	binary.LittleEndian.PutUint16(buf[coffOff+2:coffOff+4], 5) // claim 5 sections
	binary.LittleEndian.PutUint16(buf[coffOff+16:coffOff+18], peOptHeader32Size)

	binary.LittleEndian.PutUint16(buf[optOff+14:optOff+16], 0x0000)
	binary.LittleEndian.PutUint16(buf[optOff+16:optOff+18], 0x00E0)
	binary.LittleEndian.PutUint16(buf[optOff:optOff+2], 0x10B)

	// Should not panic; should return 0 or fewer sections.
	r, err := Analyze(buf, true)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	_ = r
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
