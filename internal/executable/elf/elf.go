package elf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/supunhg/filo-go/internal/entropy"
)

// Result holds ELF analysis results.
type Result struct {
	Class       string    `json:"class"`
	Data        string    `json:"data"`
	OSABI       string    `json:"osabi"`
	Type        string    `json:"type"`
	Machine     string    `json:"machine"`
	EntryPoint  uint64    `json:"entry_point"`
	Sections    []Section `json:"sections"`
	Segments    []Segment `json:"segments"`
	Security    *Security `json:"security,omitempty"`
	Notes       []Note    `json:"notes,omitempty"`
	DynamicDeps []string  `json:"dynamic_deps,omitempty"`
	Symbols     *Symbols  `json:"symbols,omitempty"`
}

// Section represents an ELF section.
type Section struct {
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Flags   string  `json:"flags"`
	Address uint64  `json:"address"`
	Size    uint64  `json:"size"`
	Offset  uint64  `json:"offset"`
	Entropy float64 `json:"entropy"`
}

// Segment represents an ELF program header/segment.
type Segment struct {
	Type     string `json:"type"`
	Offset   uint64 `json:"offset"`
	VAddr    uint64 `json:"vaddr"`
	PAddr    uint64 `json:"paddr"`
	FileSize uint64 `json:"file_size"`
	MemSize  uint64 `json:"mem_size"`
	Flags    string `json:"flags"`
	Align    uint64 `json:"align"`
}

// Security holds security-related information.
type Security struct {
	NX          bool   `json:"nx"`
	PIE         bool   `json:"pie"`
	Relro       string `json:"relro"`
	StackCanary bool   `json:"stack_canary"`
	Fortify     bool   `json:"fortify"`
	RPath       string `json:"rpath,omitempty"`
	RunPath     string `json:"runpath,omitempty"`
}

// Note represents an ELF note.
type Note struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// Symbols holds symbol information.
type Symbols struct {
	Imports []string `json:"imports"`
	Exports []string `json:"exports"`
}

// Analyze performs deep ELF analysis.
func Analyze(data []byte, deepScan bool) (*Result, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("ELF file too small")
	}

	// Verify ELF magic
	if data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("invalid ELF magic")
	}

	result := &Result{}

	// Parse ELF header
	result.Class = classString(data[4])
	result.Data = dataString(data[5])
	result.OSABI = osabiString(data[7])

	// Parse type and machine
	elfType := binary.LittleEndian.Uint16(data[16:18])
	result.Type = typeString(elfType)
	result.Machine = machineString(binary.LittleEndian.Uint16(data[18:20]))

	// Parse entry point
	if data[4] == 1 { // 32-bit
		result.EntryPoint = uint64(binary.LittleEndian.Uint32(data[24:28]))
	} else { // 64-bit
		result.EntryPoint = binary.LittleEndian.Uint64(data[24:32])
	}

	// Parse sections
	result.Sections = parseSections(data, data[4] == 2)

	// Parse program headers (segments)
	result.Segments = parseSegments(data, data[4] == 2)

	// Security analysis
	result.Security = analyzeSecurity(data, result.Sections, result.DynamicDeps)

	// Parse notes
	if deepScan {
		result.Notes = parseNotes(data, data[4] == 2)
	}

	// Parse dynamic dependencies
	result.DynamicDeps = parseDynamicDeps(data, result.Sections, data[4] == 2)

	// Parse symbols
	if deepScan {
		result.Symbols = parseSymbols(data, result.Sections)
	}

	return result, nil
}

// parseSections parses ELF section headers.
func parseSections(data []byte, is64 bool) []Section {
	var sections []Section

	// Get section header offset and count
	var shoff, shentsize, shnum, shstrndx uint64
	if is64 {
		shoff = binary.LittleEndian.Uint64(data[40:48])
		shentsize = uint64(binary.LittleEndian.Uint16(data[58:60]))
		shnum = uint64(binary.LittleEndian.Uint16(data[60:62]))
		shstrndx = uint64(binary.LittleEndian.Uint16(data[62:64]))
	} else {
		shoff = uint64(binary.LittleEndian.Uint32(data[32:36]))
		shentsize = uint64(binary.LittleEndian.Uint16(data[46:48]))
		shnum = uint64(binary.LittleEndian.Uint16(data[48:50]))
		shstrndx = uint64(binary.LittleEndian.Uint16(data[50:52]))
	}

	if shoff == 0 || shnum == 0 {
		return sections
	}

	// Read string table
	var strtabOff uint64
	if is64 {
		strtabOff = shoff + shstrndx*shentsize + 24
	} else {
		strtabOff = shoff + shstrndx*shentsize + 16
	}
	if int(strtabOff)+8 > len(data) {
		return sections
	}

	var strtabOffset, strtabSize uint64
	if is64 {
		strtabOffset = binary.LittleEndian.Uint64(data[strtabOff : strtabOff+8])
		strtabSize = binary.LittleEndian.Uint64(data[strtabOff+8 : strtabOff+16])
	} else {
		strtabOffset = uint64(binary.LittleEndian.Uint32(data[strtabOff : strtabOff+4]))
		strtabSize = uint64(binary.LittleEndian.Uint32(data[strtabOff+4 : strtabOff+8]))
	}

	if int(strtabOffset)+int(strtabSize) > len(data) {
		return sections
	}
	strtab := data[strtabOffset : strtabOffset+strtabSize]

	for i := uint64(0); i < shnum; i++ {
		secOff := shoff + i*shentsize
		if int(secOff)+int(shentsize) > len(data) {
			break
		}

		var nameIdx, secType, secFlags, secAddr, secSize, secOffset uint64
		if is64 {
			nameIdx = uint64(binary.LittleEndian.Uint32(data[secOff : secOff+4]))
			secType = binary.LittleEndian.Uint64(data[secOff+4 : secOff+12])
			secFlags = binary.LittleEndian.Uint64(data[secOff+8 : secOff+16])
			secAddr = binary.LittleEndian.Uint64(data[secOff+16 : secOff+24])
			secOffset = binary.LittleEndian.Uint64(data[secOff+24 : secOff+32])
			secSize = binary.LittleEndian.Uint64(data[secOff+32 : secOff+40])
		} else {
			nameIdx = uint64(binary.LittleEndian.Uint32(data[secOff : secOff+4]))
			secType = uint64(binary.LittleEndian.Uint32(data[secOff+4 : secOff+8]))
			secFlags = uint64(binary.LittleEndian.Uint32(data[secOff+8 : secOff+12]))
			secAddr = uint64(binary.LittleEndian.Uint32(data[secOff+12 : secOff+16]))
			secOffset = uint64(binary.LittleEndian.Uint32(data[secOff+16 : secOff+20]))
			secSize = uint64(binary.LittleEndian.Uint32(data[secOff+20 : secOff+24]))
		}

		// Get section name
		name := ""
		if int(nameIdx) < len(strtab) {
			end := bytes.IndexByte(strtab[nameIdx:], 0)
			if end >= 0 {
				name = string(strtab[nameIdx : nameIdx+uint64(end)])
			}
		}

		sec := Section{
			Name:    name,
			Type:    sectionTypeString(secType),
			Flags:   sectionFlagsString(secFlags),
			Address: secAddr,
			Size:    secSize,
			Offset:  secOffset,
		}

		// Calculate entropy
		if secSize > 0 && int(secOffset)+int(secSize) <= len(data) {
			sec.Entropy = entropy.Calculate(data[secOffset : secOffset+secSize])
		}

		sections = append(sections, sec)
	}

	return sections
}

// parseSegments parses ELF program headers.
func parseSegments(data []byte, is64 bool) []Segment {
	var segments []Segment

	// Get program header offset and count
	var phoff, phentsize, phnum uint64
	if is64 {
		phoff = binary.LittleEndian.Uint64(data[32:40])
		phentsize = uint64(binary.LittleEndian.Uint16(data[54:56]))
		phnum = uint64(binary.LittleEndian.Uint16(data[56:58]))
	} else {
		phoff = uint64(binary.LittleEndian.Uint32(data[28:32]))
		phentsize = uint64(binary.LittleEndian.Uint16(data[42:44]))
		phnum = uint64(binary.LittleEndian.Uint16(data[44:46]))
	}

	if phoff == 0 || phnum == 0 {
		return segments
	}

	for i := uint64(0); i < phnum; i++ {
		segOff := phoff + i*phentsize
		if int(segOff)+int(phentsize) > len(data) {
			break
		}

		var segType, segOffset, segVAddr, segPAddr, segFileSize, segMemSize, segFlags, segAlign uint64
		if is64 {
			segType = uint64(binary.LittleEndian.Uint32(data[segOff : segOff+4]))
			segFlags = binary.LittleEndian.Uint64(data[segOff+4 : segOff+12])
			segOffset = binary.LittleEndian.Uint64(data[segOff+8 : segOff+16])
			segVAddr = binary.LittleEndian.Uint64(data[segOff+16 : segOff+24])
			segPAddr = binary.LittleEndian.Uint64(data[segOff+24 : segOff+32])
			segFileSize = binary.LittleEndian.Uint64(data[segOff+32 : segOff+40])
			segMemSize = binary.LittleEndian.Uint64(data[segOff+40 : segOff+48])
			segAlign = binary.LittleEndian.Uint64(data[segOff+48 : segOff+56])
		} else {
			segType = uint64(binary.LittleEndian.Uint32(data[segOff : segOff+4]))
			segOffset = uint64(binary.LittleEndian.Uint32(data[segOff+4 : segOff+8]))
			segVAddr = uint64(binary.LittleEndian.Uint32(data[segOff+8 : segOff+12]))
			segPAddr = uint64(binary.LittleEndian.Uint32(data[segOff+12 : segOff+16]))
			segFileSize = uint64(binary.LittleEndian.Uint32(data[segOff+16 : segOff+20]))
			segMemSize = uint64(binary.LittleEndian.Uint32(data[segOff+20 : segOff+24]))
			segFlags = uint64(binary.LittleEndian.Uint32(data[segOff+24 : segOff+28]))
			segAlign = uint64(binary.LittleEndian.Uint32(data[segOff+28 : segOff+32]))
		}

		segments = append(segments, Segment{
			Type:     segmentTypeString(segType),
			Offset:   segOffset,
			VAddr:    segVAddr,
			PAddr:    segPAddr,
			FileSize: segFileSize,
			MemSize:  segMemSize,
			Flags:    segmentFlagsString(segFlags),
			Align:    segAlign,
		})
	}

	return segments
}

// analyzeSecurity analyzes ELF security features.
func analyzeSecurity(data []byte, sections []Section, dynamicDeps []string) *Security {
	sec := &Security{
		NX:          true,
		PIE:         false,
		Relro:       "None",
		StackCanary: false,
		Fortify:     false,
	}

	// Check for NX bit (GNU_STACK not executable)
	// Look for PT_GNU_STACK segment
	for _, seg := range parseSegments(data, data[4] == 2) {
		if seg.Type == "PT_GNU_STACK" {
			if strings.Contains(seg.Flags, "X") {
				sec.NX = false
			}
		}
	}

	// Check for PIE (shared object type or DYN)
	if data[4] == 2 { // 64-bit
		elfType := binary.LittleEndian.Uint16(data[16:18])
		sec.PIE = elfType == 3 // ET_DYN
	} else {
		elfType := binary.LittleEndian.Uint16(data[16:18])
		sec.PIE = elfType == 3
	}

	// Check for RELRO
	for _, s := range sections {
		if s.Name == ".got.plt" || s.Name == ".got" {
			sec.Relro = "Partial"
		}
		if s.Name == ".dynamic" && s.Flags == "ALLOC" {
			sec.Relro = "Full"
		}
	}

	// Check for stack canary
	for _, s := range sections {
		if s.Name == "__stack_chk_fail" || s.Name == "__stack_chk_guard" {
			sec.StackCanary = true
		}
	}

	// Check for FORTIFY
	for _, s := range sections {
		if strings.Contains(s.Name, "__strcpy_chk") || strings.Contains(s.Name, "__memcpy_chk") {
			sec.Fortify = true
		}
	}

	return sec
}

// parseNotes parses ELF notes.
func parseNotes(data []byte, is64 bool) []Note {
	var notes []Note

	// Look for .note sections
	for i := 0; i < len(data)-12; i++ {
		if data[i] == 'A' && data[i+1] == 'L' && data[i+2] == 'I' && data[i+3] == 'G' {
			// Found ALIGN note (common)
			notes = append(notes, Note{
				Type: "NT_GNU_PROPERTY_TYPE_0",
				Name: "GNU",
			})
			break
		}
	}

	return notes
}

// parseDynamicDeps parses DT_NEEDED entries.
func parseDynamicDeps(data []byte, sections []Section, is64 bool) []string {
	var deps []string

	// Look for .dynamic section
	for _, sec := range sections {
		if sec.Name == ".dynamic" && sec.Size > 0 && int(sec.Offset)+int(sec.Size) <= len(data) {
			var entrySize int
			if is64 {
				entrySize = 16
			} else {
				entrySize = 8
			}
			// Parse dynamic section entries
			dynData := data[sec.Offset : sec.Offset+sec.Size]
			for i := 0; i+entrySize <= len(dynData); i += entrySize {
				var tag uint64
				var strOff uint64
				if is64 {
					tag = binary.LittleEndian.Uint64(dynData[i : i+8])
					strOff = binary.LittleEndian.Uint64(dynData[i+8 : i+16])
				} else {
					tag = uint64(binary.LittleEndian.Uint32(dynData[i : i+4]))
					strOff = uint64(binary.LittleEndian.Uint32(dynData[i+4 : i+8]))
				}
				if tag == 1 { // DT_NEEDED
					// Find string in string table
					if int(strOff) < len(data) {
						end := bytes.IndexByte(data[strOff:], 0)
						if end > 0 {
							deps = append(deps, string(data[strOff:strOff+uint64(end)]))
						}
					}
				} else if tag == 0 {
					break
				}
			}
			break
		}
	}

	return deps
}

// parseSymbols parses ELF symbols.
func parseSymbols(data []byte, sections []Section) *Symbols {
	syms := &Symbols{}

	for _, sec := range sections {
		if sec.Name == ".dynsym" || sec.Name == ".symtab" {
			// Simplified - just note that symbols exist
			if sec.Size > 0 {
				syms.Imports = append(syms.Imports, fmt.Sprintf("[%s section present]", sec.Name))
			}
		}
	}

	return syms
}

func classString(class byte) string {
	switch class {
	case 1:
		return "ELF32"
	case 2:
		return "ELF64"
	default:
		return "Unknown"
	}
}

func dataString(data byte) string {
	switch data {
	case 1:
		return "2's complement, little-endian"
	case 2:
		return "2's complement, big-endian"
	default:
		return "Unknown"
	}
}

func osabiString(osabi byte) string {
	switch osabi {
	case 0:
		return "UNIX - System V"
	case 1:
		return "UNIX - HP-UX"
	case 2:
		return "UNIX - NetBSD"
	case 3:
		return "UNIX - GNU"
	case 6:
		return "UNIX - Solaris"
	case 9:
		return "UNIX - FreeBSD"
	case 12:
		return "UNIX - OpenBSD"
	case 13:
		return "UNIX - OpenVMS"
	case 14:
		return "UNIX - NonStop Kernel"
	case 15:
		return "UNIX - AROS"
	case 16:
		return "UNIX - FenixOS"
	case 17:
		return "Nuxi CloudABI"
	case 18:
		return "UNIX - Stratus Technologies OpenVOS"
	default:
		return fmt.Sprintf("Unknown (%d)", osabi)
	}
}

func typeString(t uint16) string {
	switch t {
	case 1:
		return "ET_REL (Relocatable)"
	case 2:
		return "ET_EXEC (Executable)"
	case 3:
		return "ET_DYN (Shared object)"
	case 4:
		return "ET_CORE (Core file)"
	default:
		return fmt.Sprintf("Unknown (%d)", t)
	}
}

func machineString(machine uint16) string {
	switch machine {
	case 0x01:
		return "AT&T WE 32100"
	case 0x02:
		return "SPARC"
	case 0x03:
		return "x86"
	case 0x04:
		return "Motorola 68000"
	case 0x05:
		return "Motorola 88000"
	case 0x08:
		return "MIPS R3000"
	case 0x0F:
		return "MIPS R10000"
	case 0x14:
		return "PowerPC"
	case 0x15:
		return "PowerPC 64-bit"
	case 0x16:
		return "IBM S390"
	case 0x28:
		return "ARM"
	case 0x2A:
		return "SuperH"
	case 0x32:
		return "Renesas/Hitachi H8/300"
	case 0x36:
		return "MIPS R3000 LE"
	case 0x3E:
		return "AMD x86-64"
	case 0x40:
		return "ARM AArch64"
	case 0x41:
		return "ARM 32-bit"
	case 0x8F:
		return "RISC-V"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", machine)
	}
}

func sectionTypeString(t uint64) string {
	types := map[uint64]string{
		0:          "SHT_NULL",
		1:          "SHT_PROGBITS",
		2:          "SHT_SYMTAB",
		3:          "SHT_STRTAB",
		4:          "SHT_RELA", //nolint:misspell
		5:          "SHT_HASH",
		6:          "SHT_DYNAMIC",
		7:          "SHT_NOTE",
		8:          "SHT_NOBITS",
		9:          "SHT_REL",
		11:         "SHT_DYNSYM",
		0x6ffffff0: "SHT_INIT_ARRAY",
		0x6ffffff1: "SHT_FINI_ARRAY",
		0x6ffffff2: "SHT_PREINIT_ARRAY",
		0x6ffffff3: "SHT_GROUP",
		0x6ffffff4: "SHT_SYMTAB_SHNDX",
		0x6ffffff6: "SHT_GNU_HASH",
		0x6ffffffd: "SHT_GNU_verneed",
		0x6ffffffe: "SHT_GNU_versym",
	}

	if name, ok := types[t]; ok {
		return name
	}
	return fmt.Sprintf("0x%X", t)
}

func sectionFlagsString(flags uint64) string {
	var result []string
	if flags&0x1 != 0 {
		result = append(result, "WRITE")
	}
	if flags&0x2 != 0 {
		result = append(result, "ALLOC")
	}
	if flags&0x4 != 0 {
		result = append(result, "EXECINSTR")
	}
	if flags&0x10 != 0 {
		result = append(result, "MERGE")
	}
	if flags&0x20 != 0 {
		result = append(result, "STRINGS")
	}
	if flags&0x40 != 0 {
		result = append(result, "INFO_LINK")
	}
	if flags&0x80 != 0 {
		result = append(result, "LINK_ORDER")
	}
	if flags&0x100 != 0 {
		result = append(result, "OS_NONCONFORMING")
	}
	if flags&0x200 != 0 {
		result = append(result, "GROUP")
	}
	if flags&0x400 != 0 {
		result = append(result, "TLS")
	}

	if len(result) == 0 {
		return "NONE"
	}
	return strings.Join(result, " | ")
}

func segmentTypeString(t uint64) string {
	types := map[uint64]string{
		0:          "PT_NULL",
		1:          "PT_LOAD",
		2:          "PT_DYNAMIC",
		3:          "PT_INTERP",
		4:          "PT_NOTE",
		5:          "PT_SHLIB",
		6:          "PT_PHDR",
		7:          "PT_TLS",
		0x60000000: "PT_GNU_EH_FRAME",
		0x60000001: "PT_GNU_STACK",
		0x60000002: "PT_GNU_RELRO",
	}

	if name, ok := types[t]; ok {
		return name
	}
	return fmt.Sprintf("0x%X", t)
}

func segmentFlagsString(flags uint64) string {
	var result []string
	if flags&0x4 != 0 {
		result = append(result, "R")
	}
	if flags&0x2 != 0 {
		result = append(result, "W")
	}
	if flags&0x1 != 0 {
		result = append(result, "X")
	}
	return strings.Join(result, "")
}
