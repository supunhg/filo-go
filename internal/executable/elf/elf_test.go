package elf

import (
	"encoding/binary"
	"testing"
)

// ELF32 header layout (52 bytes):
//   [0..3]   magic \x7F E L F
//   [4]      class (1=32bit, 2=64bit)
//   [5]      data (1=LE, 2=BE)
//   [6]      version
//   [7]      OS/ABI
//   [8..15]  padding
//   [16..17] type
//   [18..19] machine
//   [20..23] version
//   [24..27] entry
//   [28..31] phoff
//   [32..35] shoff
//   [36..39] flags
//   [40..41] ehdr size
//   [42..43] phdr entry size
//   [44..45] phdr count
//   [46..47] shdr entry size
//   [48..49] shdr count
//   [50..51] shstrndx
const (
	elf32EhdrSize = 52
	elf32PhdrSize = 32
	elf32ShdrSize = 40
)

// makeMinimalELF32LE synthesizes a minimal valid 32-bit little-endian ELF
// with one program header (PT_LOAD) and two section headers (.text and
// .shstrtab), plus a small string table.
//
// Layout (shstrndx=1, the second section is .shstrtab):
//   [0..51]      ELF header
//   [52..83]     1 program header (PT_LOAD, flags=5 R|X)
//   [84..123]    Section 0: .text
//   [124..163]   Section 1: .shstrtab
//   [164..200]   String table: "\x00.shstrtab\x00.text\x00"  (37 bytes)
//   [201..232]   .text raw data (32 bytes)
func makeMinimalELF32LE() []byte {
	const shstrtabSize = 37
	const sectionDataSize = 32

	shstrtabOff := uint32(elf32EhdrSize + elf32PhdrSize + 2*elf32ShdrSize) // 124
	sectionDataOff := shstrtabOff + shstrtabSize
	totalSize := int(sectionDataOff) + sectionDataSize

	buf := make([]byte, totalSize)

	// Magic + class/data
	buf[0] = 0x7F
	buf[1] = 'E'
	buf[2] = 'L'
	buf[3] = 'F'
	buf[4] = 1 // ELFCLASS32
	buf[5] = 1 // ELFDATA2LSB (little-endian)
	buf[6] = 1 // EV_CURRENT

	// Type, machine, version
	binary.LittleEndian.PutUint16(buf[16:18], 2)   // ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:20], 3)   // EM_386
	binary.LittleEndian.PutUint32(buf[20:24], 1)   // version

	// Entry point
	binary.LittleEndian.PutUint32(buf[24:28], 0x08048000)

	// Program header offset and count
	binary.LittleEndian.PutUint32(buf[28:32], uint32(elf32EhdrSize))     // phoff=52
	binary.LittleEndian.PutUint32(buf[32:36], uint32(elf32EhdrSize+elf32PhdrSize)) // shoff=84
	binary.LittleEndian.PutUint16(buf[40:42], elf32EhdrSize)             // ehdr size
	binary.LittleEndian.PutUint16(buf[42:44], elf32PhdrSize)             // phdr entry size
	binary.LittleEndian.PutUint16(buf[44:46], 1)                         // phdr count
	binary.LittleEndian.PutUint16(buf[46:48], elf32ShdrSize)             // shdr entry size
	binary.LittleEndian.PutUint16(buf[48:50], 2)                         // shdr count (.text + .shstrtab)
	binary.LittleEndian.PutUint16(buf[50:52], 1)                         // shstrndx = 1 (second section)

	// Program header: PT_LOAD (1)
	phdrOff := uint32(elf32EhdrSize)
	binary.LittleEndian.PutUint32(buf[phdrOff:phdrOff+4], 1)               // PT_LOAD
	binary.LittleEndian.PutUint32(buf[phdrOff+4:phdrOff+8], 0)             // offset
	binary.LittleEndian.PutUint32(buf[phdrOff+8:phdrOff+12], 0x08048000)   // vaddr
	binary.LittleEndian.PutUint32(buf[phdrOff+12:phdrOff+16], 0x08048000)  // paddr
	binary.LittleEndian.PutUint32(buf[phdrOff+16:phdrOff+20], uint32(totalSize)) // filesz
	binary.LittleEndian.PutUint32(buf[phdrOff+20:phdrOff+24], uint32(totalSize)) // memsz
	binary.LittleEndian.PutUint32(buf[phdrOff+24:phdrOff+28], 5)           // flags: R|X
	binary.LittleEndian.PutUint32(buf[phdrOff+28:phdrOff+32], 0x1000)      // align

	// String table: "\x00.shstrtab\x00.text\x00"
	copy(buf[shstrtabOff:], []byte{0})
	copy(buf[shstrtabOff+1:], ".shstrtab\x00")
	copy(buf[shstrtabOff+11:], ".text\x00")

	// Section 0: .text
	shdr0Off := uint32(elf32EhdrSize + elf32PhdrSize)
	binary.LittleEndian.PutUint32(buf[shdr0Off:shdr0Off+4], 11)         // name offset in strtab
	binary.LittleEndian.PutUint32(buf[shdr0Off+4:shdr0Off+8], 1)        // SHT_PROGBITS
	binary.LittleEndian.PutUint32(buf[shdr0Off+8:shdr0Off+12], 6)       // flags: WRITE|ALLOC|EXECINSTR
	binary.LittleEndian.PutUint32(buf[shdr0Off+12:shdr0Off+16], 0x08048000+uint32(sectionDataOff))
	binary.LittleEndian.PutUint32(buf[shdr0Off+16:shdr0Off+20], sectionDataOff) // offset
	binary.LittleEndian.PutUint32(buf[shdr0Off+20:shdr0Off+24], sectionDataSize) // size

	// Section 1: .shstrtab
	shdr1Off := shdr0Off + elf32ShdrSize
	binary.LittleEndian.PutUint32(buf[shdr1Off:shdr1Off+4], 1)          // name offset in strtab
	binary.LittleEndian.PutUint32(buf[shdr1Off+4:shdr1Off+8], 3)        // SHT_STRTAB
	binary.LittleEndian.PutUint32(buf[shdr1Off+12:shdr1Off+16], 0)      // addr
	binary.LittleEndian.PutUint32(buf[shdr1Off+16:shdr1Off+20], shstrtabOff) // offset
	binary.LittleEndian.PutUint32(buf[shdr1Off+20:shdr1Off+24], shstrtabSize) // size

	// Section data
	for i := uint32(0); i < sectionDataSize; i++ {
		buf[sectionDataOff+i] = byte(i * 7)
	}

	return buf
}

func TestAnalyzeELF32Minimal(t *testing.T) {
	data := makeMinimalELF32LE()
	r, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if r.Class != "ELF32" {
		t.Errorf("Class = %q, want %q", r.Class, "ELF32")
	}
	if r.Data != "2's complement, little-endian" {
		t.Errorf("Data = %q, want LE", r.Data)
	}
	if r.Type != "ET_EXEC (Executable)" {
		t.Errorf("Type = %q, want %q", r.Type, "ET_EXEC (Executable)")
	}
	if r.Machine != "x86" {
		t.Errorf("Machine = %q, want %q", r.Machine, "x86")
	}
	if r.EntryPoint != 0x08048000 {
		t.Errorf("EntryPoint = 0x%X, want 0x08048000", r.EntryPoint)
	}
}

func TestAnalyzeELFBadMagic(t *testing.T) {
	data := makeMinimalELF32LE()
	data[1] = 'X' // corrupt magic
	if _, err := Analyze(data, false); err == nil {
		t.Error("expected error for bad magic")
	}
}

func TestAnalyzeELFTooSmall(t *testing.T) {
	if _, err := Analyze([]byte{0x7F, 'E', 'L', 'F', 1, 1}, false); err == nil {
		t.Error("expected error for too-small data")
	}
}

func TestAnalyzeELFDeepScan(t *testing.T) {
	data := makeMinimalELF32LE()
	r, err := Analyze(data, true)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// Deep scan: Security analysis should be populated
	if r.Security == nil {
		t.Error("expected Security to be populated with deepScan=true")
	}
}

func TestClassString(t *testing.T) {
	tests := []struct {
		class byte
		want  string
	}{
		{1, "ELF32"},
		{2, "ELF64"},
		{99, "Unknown"},
	}
	for _, tt := range tests {
		if got := classString(tt.class); got != tt.want {
			t.Errorf("classString(%d) = %q, want %q", tt.class, got, tt.want)
		}
	}
}

func TestDataString(t *testing.T) {
	tests := []struct {
		data byte
		want string
	}{
		{1, "2's complement, little-endian"},
		{2, "2's complement, big-endian"},
		{99, "Unknown"},
	}
	for _, tt := range tests {
		if got := dataString(tt.data); got != tt.want {
			t.Errorf("dataString(%d) = %q, want %q", tt.data, got, tt.want)
		}
	}
}

func TestOSABIString(t *testing.T) {
	tests := []struct {
		osabi byte
		want  string
	}{
		{0, "UNIX - System V"},
		{3, "UNIX - GNU"},
		{9, "UNIX - FreeBSD"},
		{99, "Unknown (99)"},
	}
	for _, tt := range tests {
		if got := osabiString(tt.osabi); got != tt.want {
			t.Errorf("osabiString(%d) = %q, want %q", tt.osabi, got, tt.want)
		}
	}
}

func TestTypeString(t *testing.T) {
	tests := []struct {
		t    uint16
		want string
	}{
		{1, "ET_REL (Relocatable)"},
		{2, "ET_EXEC (Executable)"},
		{3, "ET_DYN (Shared object)"},
		{4, "ET_CORE (Core file)"},
		{99, "Unknown (99)"},
	}
	for _, tt := range tests {
		if got := typeString(tt.t); got != tt.want {
			t.Errorf("typeString(%d) = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestMachineString(t *testing.T) {
	tests := []struct {
		machine uint16
		want    string
	}{
		{0x03, "x86"},
		{0x3E, "AMD x86-64"},
		{0x28, "ARM"},
		{0x40, "ARM AArch64"},
		{0x8F, "RISC-V"},
		{0xFFFF, "Unknown (0xFFFF)"},
	}
	for _, tt := range tests {
		if got := machineString(tt.machine); got != tt.want {
			t.Errorf("machineString(0x%X) = %q, want %q", tt.machine, got, tt.want)
		}
	}
}

func TestSectionTypeString(t *testing.T) {
	tests := []struct {
		t    uint64
		want string
	}{
		{0, "SHT_NULL"},
		{1, "SHT_PROGBITS"},
		{2, "SHT_SYMTAB"},
		{3, "SHT_STRTAB"},
		{8, "SHT_NOBITS"},
		{11, "SHT_DYNSYM"},
		{0x99999, "0x99999"}, // unknown
	}
	for _, tt := range tests {
		if got := sectionTypeString(tt.t); got != tt.want {
			t.Errorf("sectionTypeString(0x%X) = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestSectionFlagsString(t *testing.T) {
	tests := []struct {
		flags uint64
		want  string
	}{
		{0, "NONE"},
		{1, "WRITE"},
		{2, "ALLOC"},
		{4, "EXECINSTR"},
		{3, "WRITE | ALLOC"},
		{6, "ALLOC | EXECINSTR"},
		{7, "WRITE | ALLOC | EXECINSTR"},
	}
	for _, tt := range tests {
		if got := sectionFlagsString(tt.flags); got != tt.want {
			t.Errorf("sectionFlagsString(0x%X) = %q, want %q", tt.flags, got, tt.want)
		}
	}
}

func TestSegmentTypeString(t *testing.T) {
	tests := []struct {
		t    uint64
		want string
	}{
		{0, "PT_NULL"},
		{1, "PT_LOAD"},
		{2, "PT_DYNAMIC"},
		{3, "PT_INTERP"},
		{6, "PT_PHDR"},
		{0x60000000, "PT_GNU_EH_FRAME"},
		{0x60000001, "PT_GNU_STACK"},
		{0x60000002, "PT_GNU_RELRO"},
		{0x99999, "0x99999"},
	}
	for _, tt := range tests {
		if got := segmentTypeString(tt.t); got != tt.want {
			t.Errorf("segmentTypeString(0x%X) = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestSegmentFlagsString(t *testing.T) {
	tests := []struct {
		flags uint64
		want  string
	}{
		{0, ""},
		{4, "R"},
		{2, "W"},
		{1, "X"},
		{6, "RW"},
		{7, "RWX"},
		{5, "RX"},
	}
	for _, tt := range tests {
		if got := segmentFlagsString(tt.flags); got != tt.want {
			t.Errorf("segmentFlagsString(0x%X) = %q, want %q", tt.flags, got, tt.want)
		}
	}
}

func TestParseSectionsELFMagical(t *testing.T) {
	data := makeMinimalELF32LE()
	sections := parseSections(data, false)
	if len(sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(sections))
	}
	// Section 0 is .text, section 1 is .shstrtab.
	if sections[0].Name != ".text" {
		t.Errorf("section 0 name = %q, want .text", sections[0].Name)
	}
	if sections[0].Entropy <= 0 {
		t.Errorf("section 0 entropy should be > 0, got %f", sections[0].Entropy)
	}
	if sections[1].Name != ".shstrtab" {
		t.Errorf("section 1 name = %q, want .shstrtab", sections[1].Name)
	}
}

func TestParseSegmentsELF(t *testing.T) {
	data := makeMinimalELF32LE()
	segments := parseSegments(data, false)
	if len(segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segments))
	}
	if segments[0].Type != "PT_LOAD" {
		t.Errorf("segment 0 type = %q, want PT_LOAD", segments[0].Type)
	}
	if segments[0].VAddr != 0x08048000 {
		t.Errorf("segment 0 vaddr = 0x%X, want 0x08048000", segments[0].VAddr)
	}
}

func TestParseNotesELF(t *testing.T) {
	data := makeMinimalELF32LE()
	notes := parseNotes(data, false)
	// Our minimal ELF has no notes, so should be empty
	if len(notes) != 0 {
		t.Errorf("expected 0 notes, got %d", len(notes))
	}
}

func TestParseNotesWithALIGN(t *testing.T) {
	// Inject "ALIGN" magic in the data
	data := makeMinimalELF32LE()
	// Place "ALIG" marker somewhere
	copy(data[200:204], []byte("ALIG"))
	notes := parseNotes(data, false)
	if len(notes) != 1 {
		t.Fatalf("expected 1 note, got %d", len(notes))
	}
	if notes[0].Type != "NT_GNU_PROPERTY_TYPE_0" {
		t.Errorf("note type = %q, want NT_GNU_PROPERTY_TYPE_0", notes[0].Type)
	}
	if notes[0].Name != "GNU" {
		t.Errorf("note name = %q, want GNU", notes[0].Name)
	}
}

func TestParseDynamicDepsNoDynamic(t *testing.T) {
	data := makeMinimalELF32LE()
	// Our minimal ELF has no .dynamic section
	sections := parseSections(data, false)
	deps := parseDynamicDeps(data, sections, false)
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d: %v", len(deps), deps)
	}
}

func TestParseSymbolsNoSymbols(t *testing.T) {
	data := makeMinimalELF32LE()
	sections := parseSections(data, false)
	syms := parseSymbols(data, sections)
	// Our minimal ELF has no .symtab or .dynsym
	if len(syms.Imports) != 0 {
		t.Errorf("expected 0 imports, got %d", len(syms.Imports))
	}
}

func TestResultStructure(t *testing.T) {
	r := &Result{
		Class:      "ELF64",
		Data:       "2's complement, little-endian",
		Type:       "ET_DYN (Shared object)",
		Machine:    "AMD x86-64",
		EntryPoint: 0x401000,
	}
	if r.Class != "ELF64" {
		t.Error("Class not set")
	}
	if r.Machine != "AMD x86-64" {
		t.Error("Machine not set")
	}
}

func TestSegmentStructure(t *testing.T) {
	s := Segment{
		Type:     "PT_LOAD",
		Offset:   0,
		VAddr:    0x400000,
		PAddr:    0x400000,
		FileSize: 0x1000,
		MemSize:  0x1000,
		Flags:    "RX",
		Align:    0x1000,
	}
	if s.Type != "PT_LOAD" {
		t.Error("Type not set")
	}
	if s.Flags != "RX" {
		t.Error("Flags not set")
	}
}
