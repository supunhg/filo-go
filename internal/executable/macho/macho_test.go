package macho

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildLE32Header builds a minimal 32-bit little-endian Mach-O header (MH_EXECUTE).
// The first 4 bytes are the magic 0xFEEDFACE, followed by cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags.
func buildLE32Header(cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags uint32) []byte {
	buf := make([]byte, 28)
	buf[0] = 0xFE
	buf[1] = 0xED
	buf[2] = 0xFA
	buf[3] = 0xCE
	binary.LittleEndian.PutUint32(buf[4:8], cputype)
	binary.LittleEndian.PutUint32(buf[8:12], cpusubtype)
	binary.LittleEndian.PutUint32(buf[12:16], filetype)
	binary.LittleEndian.PutUint32(buf[16:20], ncmds)
	binary.LittleEndian.PutUint32(buf[20:24], sizeofcmds)
	binary.LittleEndian.PutUint32(buf[24:28], flags)
	return buf
}

// buildLE64Header builds a minimal 64-bit little-endian Mach-O header (MH_EXECUTE_64).
// The first 4 bytes are the magic 0xFEEDFACF.
func buildLE64Header(cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags uint32) []byte {
	buf := make([]byte, 32)
	buf[0] = 0xFE
	buf[1] = 0xED
	buf[2] = 0xFA
	buf[3] = 0xCF
	binary.LittleEndian.PutUint32(buf[4:8], cputype)
	binary.LittleEndian.PutUint32(buf[8:12], cpusubtype)
	binary.LittleEndian.PutUint32(buf[12:16], filetype)
	binary.LittleEndian.PutUint32(buf[16:20], ncmds)
	binary.LittleEndian.PutUint32(buf[20:24], sizeofcmds)
	binary.LittleEndian.PutUint32(buf[24:28], flags)
	// 4 bytes reserved for 64-bit
	return buf
}

func TestAnalyzeTooSmall(t *testing.T) {
	_, err := Analyze([]byte{0xFE, 0xED, 0xFA}, false)
	if err == nil {
		t.Fatal("expected error for too-small input")
	}
	if !strings.Contains(err.Error(), "too small") {
		t.Errorf("expected 'too small' error, got %q", err)
	}
}

func TestAnalyzeInvalidMagic(t *testing.T) {
	_, err := Analyze([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}, false)
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("expected 'magic' error, got %q", err)
	}
}

func TestAnalyzeLE32(t *testing.T) {
	data := buildLE32Header(0x00000007, 0x03, 0x02, 0, 0, 0) // x86
	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Bits != 32 {
		t.Errorf("expected Bits=32, got %d", result.Bits)
	}
	if result.Endian != "little" {
		t.Errorf("expected Endian='little', got %q", result.Endian)
	}
	if result.CPU != "x86" {
		t.Errorf("expected CPU='x86', got %q", result.CPU)
	}
	if !strings.Contains(result.Type, "32-bit") {
		t.Errorf("expected Type to contain '32-bit', got %q", result.Type)
	}
}

func TestAnalyzeLE64(t *testing.T) {
	data := buildLE64Header(0x01000007, 0x03, 0x02, 0, 0, 0) // x86_64
	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Bits != 64 {
		t.Errorf("expected Bits=64, got %d", result.Bits)
	}
	if result.Endian != "little" {
		t.Errorf("expected Endian='little', got %q", result.Endian)
	}
	if result.CPU != "x86_64" {
		t.Errorf("expected CPU='x86_64', got %q", result.CPU)
	}
	if !strings.Contains(result.Type, "64-bit") {
		t.Errorf("expected Type to contain '64-bit', got %q", result.Type)
	}
}

func TestAnalyzeBE32(t *testing.T) {
	// 0xCEFAEDFE = 32-bit, big-endian
	data := []byte{0xCE, 0xFA, 0xED, 0xFE, 0, 0, 0, 0x07, 0, 0, 0, 0x03, 0, 0, 0, 0x02, 0, 0, 0, 0}
	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Bits != 32 {
		t.Errorf("expected Bits=32, got %d", result.Bits)
	}
	if result.Endian != "big" {
		t.Errorf("expected Endian='big', got %q", result.Endian)
	}
}

func TestAnalyzeBE64(t *testing.T) {
	// 0xCFFAEDFE = 64-bit, big-endian
	data := []byte{0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Bits != 64 {
		t.Errorf("expected Bits=64, got %d", result.Bits)
	}
	if result.Endian != "big" {
		t.Errorf("expected Endian='big', got %q", result.Endian)
	}
}

func TestAnalyzeLE32WithLoadCommands(t *testing.T) {
	// Header (28 bytes) + 1 LC_SEGMENT (48 bytes minimum for 32-bit)
	segCmd := make([]byte, 48)
	binary.LittleEndian.PutUint32(segCmd[0:4], 0x01)   // LC_SEGMENT
	binary.LittleEndian.PutUint32(segCmd[4:8], 48)     // cmdsize
	copy(segCmd[8:24], "__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	binary.LittleEndian.PutUint32(segCmd[24:28], 0x1000) // vmaddr
	binary.LittleEndian.PutUint32(segCmd[28:32], 0x1000) // vmsize
	binary.LittleEndian.PutUint32(segCmd[32:36], 0)      // fileoff
	binary.LittleEndian.PutUint32(segCmd[36:40], 0x1000) // filesize
	binary.LittleEndian.PutUint32(segCmd[40:44], 0x07)   // maxprot
	binary.LittleEndian.PutUint32(segCmd[44:48], 0x05)   // initprot

	data := buildLE32Header(0x07, 0x03, 0x02, 1, 48, 0)
	data = append(data, segCmd...)

	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.LoadCommands) != 1 {
		t.Fatalf("expected 1 load command, got %d", len(result.LoadCommands))
	}
	if result.LoadCommands[0].Type != "LC_SEGMENT" {
		t.Errorf("expected LC_SEGMENT, got %q", result.LoadCommands[0].Type)
	}
	if len(result.Segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(result.Segments))
	}
	if result.Segments[0].Name != "__TEXT" {
		t.Errorf("expected segment name '__TEXT', got %q", result.Segments[0].Name)
	}
}

func TestAnalyzeLE64WithSegment64(t *testing.T) {
	// 64-bit header (32 bytes) + LC_SEGMENT_64 (72 bytes minimum)
	segCmd := make([]byte, 72)
	binary.LittleEndian.PutUint32(segCmd[0:4], 0x19)   // LC_SEGMENT_64
	binary.LittleEndian.PutUint32(segCmd[4:8], 72)     // cmdsize
	copy(segCmd[8:24], "__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	binary.LittleEndian.PutUint64(segCmd[24:32], 0x1000) // vmaddr
	binary.LittleEndian.PutUint64(segCmd[32:40], 0x1000) // vmsize
	binary.LittleEndian.PutUint64(segCmd[40:48], 0)      // fileoff
	binary.LittleEndian.PutUint64(segCmd[48:56], 0x1000) // filesize
	binary.LittleEndian.PutUint32(segCmd[56:60], 0x07)   // maxprot
	binary.LittleEndian.PutUint32(segCmd[60:64], 0x05)   // initprot
	binary.LittleEndian.PutUint32(segCmd[64:68], 0)      // nsects
	binary.LittleEndian.PutUint32(segCmd[68:72], 0)      // flags

	data := buildLE64Header(0x01000007, 0x03, 0x02, 1, 72, 0)
	data = append(data, segCmd...)

	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.LoadCommands) != 1 {
		t.Fatalf("expected 1 load command, got %d", len(result.LoadCommands))
	}
	if result.LoadCommands[0].Type != "LC_SEGMENT_64" {
		t.Errorf("expected LC_SEGMENT_64, got %q", result.LoadCommands[0].Type)
	}
	if len(result.Segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(result.Segments))
	}
	if result.Segments[0].Name != "__DATA" {
		t.Errorf("expected segment name '__DATA', got %q", result.Segments[0].Name)
	}
}

func TestAnalyzeDylib(t *testing.T) {
	// LC_LOAD_DYLIB (0xC), structure layout:
	//   cmd(4) cmdsize(4) dylib.name.offset(4) dylib.timestamp(4) dylib.current_version(4) dylib.compat_version(4)
	// The dylib struct starts at offset 8 of the load command, and its name.offset
	// is a relative offset from the start of the load command to the name string.
	// We put the name at offset 24 (8 dylib-header bytes + 4 version fields + 8 padding).
	name := "/usr/lib/libSystem.B.dylib\x00"
	dylibCmd := make([]byte, 24+len(name))
	binary.LittleEndian.PutUint32(dylibCmd[0:4], 0x0C)   // LC_LOAD_DYLIB
	binary.LittleEndian.PutUint32(dylibCmd[4:8], uint32(len(dylibCmd))) // cmdsize
	binary.LittleEndian.PutUint32(dylibCmd[8:12], 24)    // dylib.name.offset (from start of LC)
	binary.LittleEndian.PutUint32(dylibCmd[12:16], 1234) // dylib.timestamp
	binary.LittleEndian.PutUint32(dylibCmd[16:20], 0)    // current_version
	binary.LittleEndian.PutUint32(dylibCmd[20:24], 0)    // compat_version
	copy(dylibCmd[24:], name)

	data := buildLE32Header(0x07, 0x03, 0x02, 1, uint32(len(dylibCmd)), 0)
	data = append(data, dylibCmd...)

	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Dylibs) != 1 {
		t.Fatalf("expected 1 dylib, got %d", len(result.Dylibs))
	}
	if !strings.Contains(result.Dylibs[0].Name, "libSystem") {
		t.Errorf("expected dylib name to contain 'libSystem', got %q", result.Dylibs[0].Name)
	}
	if result.Dylibs[0].Timestamp != 1234 {
		t.Errorf("expected timestamp=1234, got %d", result.Dylibs[0].Timestamp)
	}
}

func TestAnalyzeCodeSignature(t *testing.T) {
	// LC_CODE_SIGNATURE (0x1D), 16 bytes.
	// The parser reads sig.Size from offset+8 and sig.Offset from offset+12.
	sigCmd := make([]byte, 16)
	binary.LittleEndian.PutUint32(sigCmd[0:4], 0x1D)   // LC_CODE_SIGNATURE
	binary.LittleEndian.PutUint32(sigCmd[4:8], 16)     // cmdsize
	binary.LittleEndian.PutUint32(sigCmd[8:12], 0x200) // parsed as sig.Size
	binary.LittleEndian.PutUint32(sigCmd[12:16], 0x1000) // parsed as sig.Offset

	data := buildLE32Header(0x07, 0x03, 0x02, 1, 16, 0)
	data = append(data, sigCmd...)

	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CodeSignature == nil {
		t.Fatal("expected code signature to be set")
	}
	if !result.CodeSignature.Present {
		t.Error("expected code signature to be present")
	}
	if result.CodeSignature.Size != 0x200 {
		t.Errorf("expected size=0x200, got %d", result.CodeSignature.Size)
	}
}

func TestAnalyzeTruncatedLoadCommand(t *testing.T) {
	// Header says 1 cmd but the buffer doesn't have enough space for it.
	data := buildLE32Header(0x07, 0x03, 0x02, 1, 16, 0)
	// No load command data appended.
	result, err := Analyze(data, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The loop should break safely and return with no load commands.
	if len(result.LoadCommands) != 0 {
		t.Errorf("expected 0 load commands, got %d", len(result.LoadCommands))
	}
}

func TestAnalyzeFatBinary(t *testing.T) {
	// Build a fat header: magic(4) + nfat_arch(4) + 1 fat_arch(20) = 28 bytes
	// Then embed a real 32-bit Mach-O starting at offset 4096 (page aligned).
	fat := make([]byte, 28)
	fat[0] = 0xCA
	fat[1] = 0xFE
	fat[2] = 0xBA
	fat[3] = 0xBE
	binary.BigEndian.PutUint32(fat[4:8], 1) // nfat_arch
	binary.BigEndian.PutUint32(fat[8:12], 0x07)  // cputype x86
	binary.BigEndian.PutUint32(fat[12:16], 3)    // cpusubtype
	binary.BigEndian.PutUint32(fat[16:20], 4096) // offset
	binary.BigEndian.PutUint32(fat[20:24], 28)   // size
	binary.BigEndian.PutUint32(fat[24:28], 12)   // align

	// Pad to offset 4096
	fat = append(fat, make([]byte, 4096-28)...)
	// Append a real 32-bit Mach-O
	macho := buildLE32Header(0x07, 0x03, 0x02, 0, 0, 0)
	fat = append(fat, macho...)

	result, err := Analyze(fat, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FatHeader == nil {
		t.Fatal("expected FatHeader to be set")
	}
	if result.FatHeader.NFatArch != 1 {
		t.Errorf("expected NFatArch=1, got %d", result.FatHeader.NFatArch)
	}
	if len(result.FatHeader.Arches) != 1 {
		t.Errorf("expected 1 arch in fat header, got %d", len(result.FatHeader.Arches))
	}
	if result.FatHeader.Arches[0].CPU != "x86" {
		t.Errorf("expected fat arch CPU='x86', got %q", result.FatHeader.Arches[0].CPU)
	}
	if result.CPU != "x86" {
		t.Errorf("expected inner CPU='x86', got %q", result.CPU)
	}
}

func TestAnalyzeFatTooManyArches(t *testing.T) {
	// nfat_arch > 100 should fail sanity check
	fat := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x01, 0x00}
	_, err := Analyze(fat, false)
	if err == nil {
		t.Fatal("expected error for too many arches")
	}
}

func TestAnalyzeFatTooSmall(t *testing.T) {
	fat := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	_, err := Analyze(fat, false)
	if err == nil {
		t.Fatal("expected error for fat binary too small")
	}
}

func TestCPUStringKnown(t *testing.T) {
	tests := []struct {
		cpu  uint32
		want string
	}{
		{0x00000007, "x86"},
		{0x01000007, "x86_64"},
		{0x0000000C, "ARM"},
		{0x0100000C, "ARM64"},
		{0x0000000E, "PowerPC"},
		{0x0100000E, "PowerPC64"},
	}
	for _, tt := range tests {
		got := cpuString(tt.cpu)
		if got != tt.want {
			t.Errorf("cpuString(0x%X) = %q, want %q", tt.cpu, got, tt.want)
		}
	}
}

func TestCPUStringUnknown(t *testing.T) {
	got := cpuString(0x99999999)
	if !strings.Contains(got, "Unknown") {
		t.Errorf("expected 'Unknown' in cpuString for unknown CPU type, got %q", got)
	}
}

func TestLoadCommandStringKnown(t *testing.T) {
	tests := []struct {
		cmd  uint32
		want string
	}{
		{0x01, "LC_SEGMENT"},
		{0x02, "LC_SYMTAB"},
		{0x0C, "LC_LOAD_DYLIB"},
		{0x19, "LC_SEGMENT_64"},
		{0x1D, "LC_CODE_SIGNATURE"},
	}
	for _, tt := range tests {
		got := loadCommandString(tt.cmd)
		if got != tt.want {
			t.Errorf("loadCommandString(0x%X) = %q, want %q", tt.cmd, got, tt.want)
		}
	}
}

func TestLoadCommandStringUnknown(t *testing.T) {
	got := loadCommandString(0xDEADBEEF)
	if !strings.Contains(got, "0x") {
		t.Errorf("expected '0x' in unknown load command string, got %q", got)
	}
}

func TestParseSegmentTruncated(t *testing.T) {
	// Pass a too-small buffer
	seg := parseSegment([]byte{0x00, 0x00, 0x00, 0x00}, 0, 0x01, false, false)
	if seg != nil {
		t.Errorf("expected nil for truncated segment, got %+v", seg)
	}
}

func TestParseDylibTruncated(t *testing.T) {
	dylib := parseDylib([]byte{0x00, 0x00, 0x00}, 0, false)
	if dylib != nil {
		t.Errorf("expected nil for truncated dylib, got %+v", dylib)
	}
}

func TestParseCodeSignatureTruncated(t *testing.T) {
	sig := parseCodeSignature([]byte{0x00, 0x00, 0x00}, 0, false)
	if sig != nil {
		t.Errorf("expected nil for truncated code signature, got %+v", sig)
	}
}
