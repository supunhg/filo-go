package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Result holds Mach-O analysis results.
type Result struct {
	Type          string         `json:"type"`
	CPU           string         `json:"cpu"`
	Bits          int            `json:"bits"`
	Endian        string         `json:"endian"`
	FatHeader     *FatHeader     `json:"fat_header,omitempty"`
	LoadCommands  []LoadCommand  `json:"load_commands"`
	Segments      []Segment      `json:"segments"`
	CodeSignature *CodeSignature `json:"code_signature,omitempty"`
	Dylibs        []Dylib        `json:"dylibs,omitempty"`
	EntryPoints   []uint64       `json:"entry_points,omitempty"`
}

// FatHeader represents a universal (fat) binary header.
type FatHeader struct {
	NFatArch int       `json:"nfat_arch"`
	Arches   []FatArch `json:"arches"`
}

// FatArch represents an architecture in a fat binary.
type FatArch struct {
	CPU     string `json:"cpu"`
	CPUType uint32 `json:"cpu_type"`
	Offset  uint32 `json:"offset"`
	Size    uint32 `json:"size"`
	Align   uint32 `json:"align"`
}

// LoadCommand represents a Mach-O load command.
type LoadCommand struct {
	Type string `json:"type"`
	Size uint32 `json:"size"`
}

// Segment represents a Mach-O segment.
type Segment struct {
	Name     string `json:"name"`
	Address  uint64 `json:"address"`
	Size     uint64 `json:"size"`
	MaxProt  string `json:"max_prot"`
	InitProt string `json:"init_prot"`
	NumSects uint32 `json:"num_sections"`
}

// CodeSignature represents code signature information.
type CodeSignature struct {
	Present bool   `json:"present"`
	Size    uint32 `json:"size,omitempty"`
	Offset  uint32 `json:"offset,omitempty"`
}

// Dylib represents a dynamic library dependency.
type Dylib struct {
	Name           string `json:"name"`
	CompatVersion  string `json:"compat_version"`
	CurrentVersion string `json:"current_version"`
	Timestamp      uint32 `json:"timestamp,omitempty"`
}

// Analyze performs deep Mach-O analysis.
func Analyze(data []byte, deepScan bool) (*Result, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("Mach-O file too small")
	}

	// Check for universal binary (fat)
	if data[0] == 0xCA && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE {
		return analyzeFat(data, deepScan)
	}

	// Check for single Mach-O
	return analyzeSingleMachO(data, deepScan)
}

// analyzeFat analyzes a universal (fat) binary.
func analyzeFat(data []byte, deepScan bool) (*Result, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("Fat binary too small")
	}

	nfatArch := binary.BigEndian.Uint32(data[4:8])
	if nfatArch > 100 { // Sanity check
		return nil, fmt.Errorf("invalid number of architectures: %d", nfatArch)
	}

	fatHeader := &FatHeader{
		NFatArch: int(nfatArch),
		Arches:   make([]FatArch, 0, nfatArch),
	}

	for i := uint32(0); i < nfatArch; i++ {
		offset := 8 + i*20
		if int(offset)+20 > len(data) {
			break
		}

		arch := FatArch{
			CPUType: binary.BigEndian.Uint32(data[offset : offset+4]),
			Offset:  binary.BigEndian.Uint32(data[offset+8 : offset+12]),
			Size:    binary.BigEndian.Uint32(data[offset+12 : offset+16]),
			Align:   binary.BigEndian.Uint32(data[offset+16 : offset+20]),
		}
		arch.CPU = cpuString(arch.CPUType)
		fatHeader.Arches = append(fatHeader.Arches, arch)
	}

	// Analyze first architecture
	if len(fatHeader.Arches) > 0 {
		arch := fatHeader.Arches[0]
		if int(arch.Offset)+int(arch.Size) <= len(data) {
			singleData := data[arch.Offset : arch.Offset+arch.Size]
			result, err := analyzeSingleMachO(singleData, deepScan)
			if err != nil {
				return nil, err
			}
			result.FatHeader = fatHeader
			return result, nil
		}
	}

	return nil, fmt.Errorf("could not analyze any architecture")
}

// analyzeSingleMachO analyzes a single Mach-O binary.
func analyzeSingleMachO(data []byte, deepScan bool) (*Result, error) {
	result := &Result{
		LoadCommands: []LoadCommand{},
		Segments:     []Segment{},
	}

	// Determine magic and endianness
	var is64 bool
	var isSwap bool

	if data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA {
		// 0xFEEDFACF = 64-bit, little-endian
		// 0xFEEDFACE = 32-bit, little-endian
		is64 = data[3] == 0xCF
		isSwap = false
		result.Endian = "little"
	} else if data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED {
		// 0xCEFAEDFE = 32-bit, big-endian
		is64 = false
		isSwap = true
		result.Endian = "big"
	} else if data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED {
		// 0xCFFAEDFE = 64-bit, big-endian
		is64 = true
		isSwap = true
		result.Endian = "big"
	} else if data[0] == 0xBE && data[1] == 0xBA && data[2] == 0xFE {
		// 0xBEBAFECA = 32-bit, big-endian (old)
		is64 = false
		isSwap = true
		result.Endian = "big"
	} else {
		return nil, fmt.Errorf("invalid Mach-O magic")
	}

	if is64 {
		result.Bits = 64
		result.Type = "MH_EXECUTE (64-bit)"
	} else {
		result.Bits = 32
		result.Type = "MH_EXECUTE (32-bit)"
	}

	// Parse header
	var cputype, cpusubtype uint32
	var ncmds uint32
	if isSwap {
		if is64 {
			cputype = binary.BigEndian.Uint32(data[4:8])
			cpusubtype = binary.BigEndian.Uint32(data[8:12])
			ncmds = binary.BigEndian.Uint32(data[16:20])
		} else {
			cputype = binary.BigEndian.Uint32(data[4:8])
			cpusubtype = binary.BigEndian.Uint32(data[8:12])
			ncmds = binary.BigEndian.Uint32(data[12:16])
		}
	} else {
		if is64 {
			cputype = binary.LittleEndian.Uint32(data[4:8])
			cpusubtype = binary.LittleEndian.Uint32(data[8:12])
			ncmds = binary.LittleEndian.Uint32(data[16:20])
		} else {
			cputype = binary.LittleEndian.Uint32(data[4:8])
			cpusubtype = binary.LittleEndian.Uint32(data[8:12])
			ncmds = binary.LittleEndian.Uint32(data[12:16])
		}
	}

	result.CPU = cpuString(cputype)
	_ = cpusubtype

	// Parse load commands
	cmdOffset := 0
	if is64 {
		cmdOffset = 32 // 64-bit header size
	} else {
		cmdOffset = 28 // 32-bit header size
	}

	for i := uint32(0); i < ncmds && cmdOffset < len(data); i++ {
		if cmdOffset+8 > len(data) {
			break
		}

		var cmdType, cmdSize uint32
		if isSwap {
			cmdType = binary.BigEndian.Uint32(data[cmdOffset : cmdOffset+4])
			cmdSize = binary.BigEndian.Uint32(data[cmdOffset+4 : cmdOffset+8])
		} else {
			cmdType = binary.LittleEndian.Uint32(data[cmdOffset : cmdOffset+4])
			cmdSize = binary.LittleEndian.Uint32(data[cmdOffset+4 : cmdOffset+8])
		}

		if cmdSize == 0 || cmdSize > 1024*1024 { // Sanity check
			break
		}

		cmd := LoadCommand{
			Type: loadCommandString(cmdType),
			Size: cmdSize,
		}
		result.LoadCommands = append(result.LoadCommands, cmd)

		// Parse segment commands
		if cmdType == 0x1 || cmdType == 0x19 { // LC_SEGMENT or LC_SEGMENT_64
			seg := parseSegment(data, cmdOffset, cmdType, isSwap, is64)
			if seg != nil {
				result.Segments = append(result.Segments, *seg)
			}
		}

		// Parse dylib commands
		if cmdType == 0xC || cmdType == 0x80000018 || cmdType == 0x8000001C { // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB
			dylib := parseDylib(data, cmdOffset, isSwap)
			if dylib != nil {
				result.Dylibs = append(result.Dylibs, *dylib)
			}
		}

		// Parse code signature
		if cmdType == 0x1D { // LC_CODE_SIGNATURE
			result.CodeSignature = parseCodeSignature(data, cmdOffset, isSwap)
		}

		cmdOffset += int(cmdSize)
	}

	return result, nil
}

// parseSegment parses a segment load command.
func parseSegment(data []byte, offset int, cmdType uint32, isSwap, is64 bool) *Segment {
	seg := &Segment{}

	var nameOffset int
	var segName string

	if is64 {
		nameOffset = offset + 8
		// Segment name is 16 bytes
		if nameOffset+16 > len(data) {
			return nil
		}
		segName = strings.TrimRight(string(data[nameOffset:nameOffset+16]), "\x00")
		seg.Name = segName

		var addr, size uint64
		if isSwap {
			addr = binary.BigEndian.Uint64(data[nameOffset+16 : nameOffset+24])
			size = binary.BigEndian.Uint64(data[nameOffset+24 : nameOffset+32])
			seg.NumSects = binary.BigEndian.Uint32(data[nameOffset+40 : nameOffset+44])
		} else {
			addr = binary.LittleEndian.Uint64(data[nameOffset+16 : nameOffset+24])
			size = binary.LittleEndian.Uint64(data[nameOffset+24 : nameOffset+32])
			seg.NumSects = binary.LittleEndian.Uint32(data[nameOffset+40 : nameOffset+44])
		}
		seg.Address = addr
		seg.Size = size
	} else {
		nameOffset = offset + 8
		if nameOffset+16 > len(data) {
			return nil
		}
		segName = strings.TrimRight(string(data[nameOffset:nameOffset+16]), "\x00")
		seg.Name = segName

		var addr, size uint32
		if isSwap {
			addr = binary.BigEndian.Uint32(data[nameOffset+16 : nameOffset+20])
			size = binary.BigEndian.Uint32(data[nameOffset+20 : nameOffset+24])
			seg.NumSects = binary.BigEndian.Uint32(data[nameOffset+28 : nameOffset+32])
		} else {
			addr = binary.LittleEndian.Uint32(data[nameOffset+16 : nameOffset+20])
			size = binary.LittleEndian.Uint32(data[nameOffset+20 : nameOffset+24])
			seg.NumSects = binary.LittleEndian.Uint32(data[nameOffset+28 : nameOffset+32])
		}
		seg.Address = uint64(addr)
		seg.Size = uint64(size)
	}

	// Set protection flags (simplified)
	seg.MaxProt = "rwx"
	seg.InitProt = "r-x"

	return seg
}

// parseDylib parses a dylib load command.
func parseDylib(data []byte, offset int, isSwap bool) *Dylib {
	if offset+24 > len(data) {
		return nil
	}

	dylib := &Dylib{}

	// Get name offset
	var nameOff uint32
	if isSwap {
		nameOff = binary.BigEndian.Uint32(data[offset+8 : offset+12])
	} else {
		nameOff = binary.LittleEndian.Uint32(data[offset+8 : offset+12])
	}

	// Extract name
	nameStart := offset + int(nameOff)
	if nameStart < len(data) {
		end := bytes.IndexByte(data[nameStart:], 0)
		if end > 0 {
			dylib.Name = string(data[nameStart : nameStart+end])
		}
	}

	// Get timestamp
	if isSwap {
		dylib.Timestamp = binary.BigEndian.Uint32(data[offset+12 : offset+16])
	} else {
		dylib.Timestamp = binary.LittleEndian.Uint32(data[offset+12 : offset+16])
	}

	dylib.CompatVersion = "n/a"
	dylib.CurrentVersion = "n/a"

	return dylib
}

// parseCodeSignature parses the code signature load command.
func parseCodeSignature(data []byte, offset int, isSwap bool) *CodeSignature {
	if offset+16 > len(data) {
		return nil
	}

	sig := &CodeSignature{Present: true}

	if isSwap {
		sig.Size = binary.BigEndian.Uint32(data[offset+8 : offset+12])
		sig.Offset = binary.BigEndian.Uint32(data[offset+12 : offset+16])
	} else {
		sig.Size = binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		sig.Offset = binary.LittleEndian.Uint32(data[offset+12 : offset+16])
	}

	return sig
}

// cpuString returns string name for CPU type.
func cpuString(cputype uint32) string {
	switch cputype {
	case 0x00000007:
		return "x86"
	case 0x01000007:
		return "x86_64"
	case 0x0000000C:
		return "ARM"
	case 0x0100000C:
		return "ARM64"
	case 0x0000000D:
		return "ARM64_32"
	case 0x00000006:
		return "MC680x0"
	case 0x0000000E:
		return "PowerPC"
	case 0x0100000E:
		return "PowerPC64"
	case 0x0000000F:
		return "SPARC"
	case 0x00000011:
		return "Sparc64"
	case 0x00000012:
		return "Motorola 88000"
	case 0x00000013:
		return "i860"
	case 0x00000015:
		return "HPPA"
	case 0x00000016:
		return "Alpha"
	case 0x00000017:
		return "MIPS"
	case 0x00000019:
		return "AMD64"
	case 0x0000001C:
		return "ARM9TDMI"
	case 0x00000036:
		return "Sparc64"
	case 0x00000037:
		return "PowerPC"
	case 0x00000100:
		return "ARM64"
	case 0x00000102:
		return "ARM64_32"
	case 0x02000012:
		return "X86 ALL"
	case 0x02000007:
		return "x86 ALL"
	case 0xFF00000C:
		return "ARM ALL"
	case 0x01000006:
		return "MC680x0 ALL"
	case 0x01000015:
		return "HPPA ALL"
	case 0x01000016:
		return "Alpha ALL"
	case 0x01000017:
		return "MIPS ALL"
	case 0x01000019:
		return "AMD64 ALL"
	default:
		return fmt.Sprintf("Unknown (0x%X)", cputype)
	}
}

// loadCommandString returns string name for load command type.
func loadCommandString(cmdType uint32) string {
	commands := map[uint32]string{
		0x1:        "LC_SEGMENT",
		0x2:        "LC_SYMTAB",
		0x3:        "LC_SYMSEG",
		0x4:        "LC_THREAD",
		0x5:        "LC_UNIXTHREAD",
		0x6:        "LC_LOADFVMLIB",
		0x7:        "LC_IDFVMLIB",
		0x8:        "LC_IDENT",
		0x9:        "LC_FVMFILE",
		0xA:        "LC_PREPAGE",
		0xB:        "LC_DYSYMTAB",
		0xC:        "LC_LOAD_DYLIB",
		0xD:        "LC_ID_DYLIB",
		0xE:        "LC_LOAD_DYLINKER",
		0xF:        "LC_ID_DYLINKER",
		0x10:       "LC_PREBOUND_DYLIB",
		0x11:       "LC_ROUTINES",
		0x12:       "LC_SUB_FRAMEWORK",
		0x13:       "LC_SUB_UMBRELLA",
		0x14:       "LC_SUB_CLIENT",
		0x15:       "LC_SUB_LIBRARY",
		0x16:       "LC_TWOLEVEL_HINTS",
		0x17:       "LC_PREBIND_CKSUM",
		0x18:       "LC_LOAD_WEAK_DYLIB",
		0x19:       "LC_SEGMENT_64",
		0x1A:       "LC_ROUTINES_64",
		0x1B:       "LC_UUID",
		0x1C:       "LC_RPATH",
		0x1D:       "LC_CODE_SIGNATURE",
		0x1E:       "LC_SEGMENT_SPLIT_INFO",
		0x1F:       "LC_REEXPORT_DYLIB",
		0x20:       "LC_LAZY_LOAD_DYLIB",
		0x21:       "LC_ENCRYPTION_INFO",
		0x22:       "LC_DYLD_INFO",
		0x23:       "LC_DYLD_INFO_ONLY",
		0x24:       "LC_LOAD_UPWARD_DYLIB",
		0x25:       "LC_VERSION_MIN_MACOSX",
		0x26:       "LC_VERSION_MIN_IPHONEOS",
		0x27:       "LC_FUNCTION_STARTS",
		0x28:       "LC_DYLD_ENVIRONMENT",
		0x29:       "LC_MAIN",
		0x2A:       "LC_DATA_IN_CODE",
		0x2B:       "LC_SOURCE_VERSION",
		0x2C:       "LC_DYLIB_CODE_SIGN_DRS",
		0x2D:       "LC_ENCRYPTION_INFO_64",
		0x2E:       "LC_LINKER_OPTION",
		0x2F:       "LC_LINKER_OPTIMIZATION_HINT",
		0x30:       "LC_VERSION_MIN_TVOS",
		0x31:       "LC_VERSION_MIN_WATCHOS",
		0x32:       "LC_BUILD_VERSION",
		0x80000018: "LC_LOAD_WEAK_DYLIB",
		0x8000001C: "LC_REEXPORT_DYLIB",
	}

	if name, ok := commands[cmdType]; ok {
		return name
	}
	return fmt.Sprintf("0x%X", cmdType)
}
