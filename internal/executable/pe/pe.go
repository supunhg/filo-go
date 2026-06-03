package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// Result holds PE analysis results.
type Result struct {
	// Header info
	Machine     uint16   `json:"machine"`
	MachineStr  string   `json:"machine_str"`
	Bits        int      `json:"bits"`
	Sections    []Section `json:"sections"`
	Imports     []string `json:"imports"`
	DLLs        []string `json:"dlls"`
	Subsystem   string   `json:"subsystem"`
	ImageBase   uint64   `json:"image_base"`
	EntryPoint  uint64   `json:"entry_point"`
	Timestamp   uint32   `json:"timestamp"`
	Characteristics uint16 `json:"characteristics"`
	
	// Security features
	TLS         *TLSInfo    `json:"tls,omitempty"`
	DebugInfo   *DebugInfo  `json:"debug_info,omitempty"`
	Resources   []Resource  `json:"resources,omitempty"`
	Relocations []Reloc     `json:"relocations,omitempty"`
	
	// Rich header
	RichHeader  *RichHeader `json:"rich_header,omitempty"`
	
	// Data directories
	DataDirs    []DataDir   `json:"data_dirs,omitempty"`
}

// Section represents a PE section.
type Section struct {
	Name            string  `json:"name"`
	VirtualAddress  uint32  `json:"virtual_address"`
	VirtualSize     uint32  `json:"virtual_size"`
	RawSize         uint32  `json:"raw_size"`
	RawOffset       uint32  `json:"raw_offset"`
	Characteristics uint32  `json:"characteristics"`
	Entropy         float64 `json:"entropy"`
	Suspicious      bool    `json:"suspicious"`
	Reason          string  `json:"reason,omitempty"`
}

// TLSInfo holds TLS directory information.
type TLSInfo struct {
	HasCallbacks bool     `json:"has_callbacks"`
	CallbackAddrs []uint64 `json:"callback_addrs,omitempty"`
}

// DebugInfo holds debug directory information.
type DebugInfo struct {
	HasDebug   bool   `json:"has_debug"`
	DebugType  string `json:"debug_type,omitempty"`
	PDBPath    string `json:"pdb_path,omitempty"`
}

// Resource represents a PE resource entry.
type Resource struct {
	Type     string `json:"type"`
	ID       uint32 `json:"id"`
	Size     uint32 `json:"size"`
	Language uint16 `json:"language"`
}

// Reloc represents a base relocation.
type Reloc struct {
	VirtualAddress uint32 `json:"virtual_address"`
	Type           uint16 `json:"type"`
}

// RichHeader represents the Rich header (Microsoft specific).
type RichHeader struct {
	CompID  uint32 `json:"comp_id"`
	ToolID  uint32 `json:"tool_id"`
	BuildID uint32 `json:"build_id"`
}

// DataDir represents a data directory entry.
type DataDir struct {
	Name   string `json:"name"`
	RVA    uint32 `json:"rva"`
	Size   uint32 `json:"size"`
}

// Analyze performs deep PE analysis.
func Analyze(data []byte, deepScan bool) (*Result, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("PE file too small")
	}

	// Verify MZ signature
	if data[0] != 'M' || data[1] != 'Z' {
		return nil, fmt.Errorf("invalid MZ signature")
	}

	// Get PE header offset
	peOffset := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if int(peOffset)+24 > len(data) {
		return nil, fmt.Errorf("invalid PE header offset")
	}

	// Verify PE signature
	if data[peOffset] != 'P' || data[peOffset+1] != 'E' || data[peOffset+2] != 0 || data[peOffset+3] != 0 {
		return nil, fmt.Errorf("invalid PE signature")
	}

	result := &Result{}

	// Parse COFF header
	coffOffset := peOffset + 4
	result.Machine = binary.LittleEndian.Uint16(data[coffOffset : coffOffset+2])
	result.MachineStr = machineName(result.Machine)
	result.Characteristics = binary.LittleEndian.Uint16(data[coffOffset+18 : coffOffset+20])

	// Determine bits
	if result.Machine == 0x8664 || result.Machine == 0xAA64 {
		result.Bits = 64
	} else {
		result.Bits = 32
	}

	// Parse Optional header
	optOffset := coffOffset + 20
	magic := binary.LittleEndian.Uint16(data[optOffset : optOffset+2])

	if magic == 0x10B { // PE32
		if int(optOffset)+96 > len(data) {
			return nil, fmt.Errorf("PE32 optional header too small")
		}
		result.ImageBase = uint64(binary.LittleEndian.Uint32(data[optOffset+28 : optOffset+32]))
		result.EntryPoint = uint64(binary.LittleEndian.Uint32(data[optOffset+16 : optOffset+20]))
		result.Subsystem = subsystemName(binary.LittleEndian.Uint16(data[optOffset+68 : optOffset+70]))
	} else if magic == 0x20B { // PE32+ (64-bit)
		if int(optOffset)+112 > len(data) {
			return nil, fmt.Errorf("PE32+ optional header too small")
		}
		result.ImageBase = binary.LittleEndian.Uint64(data[optOffset+24 : optOffset+32])
		result.EntryPoint = uint64(binary.LittleEndian.Uint32(data[optOffset+16 : optOffset+20]))
		result.Subsystem = subsystemName(binary.LittleEndian.Uint16(data[optOffset+68 : optOffset+70]))
	}

	// Parse sections
	numSections := binary.LittleEndian.Uint16(data[coffOffset+2 : coffOffset+4])
	sectionOffset := optOffset + uint32(binary.LittleEndian.Uint16(data[optOffset+16:optOffset+18])) + uint32(binary.LittleEndian.Uint16(data[optOffset+14:optOffset+16]))

	result.Sections = parseSections(data, sectionOffset, numSections)

	// Parse imports
	if deepScan {
		result.Imports, result.DLLs = parseImports(data, result.Bits)
	}

	// Check for TLS callbacks
	result.TLS = checkTLS(data, result.Bits)

	// Check debug info
	result.DebugInfo = checkDebug(data, result.Bits)

	// Parse resources
	if deepScan {
		result.Resources = parseResources(data, result.Bits)
	}

	// Check for rich header
	result.RichHeader = parseRichHeader(data)

	// Parse data directories
	result.DataDirs = parseDataDirs(data, optOffset, magic)

	return result, nil
}

// parseSections parses PE section headers.
func parseSections(data []byte, offset uint32, count uint16) []Section {
	var sections []Section

	for i := uint16(0); i < count; i++ {
		secOffset := offset + uint32(i)*40
		if int(secOffset)+40 > len(data) {
			break
		}

		name := string(bytes.TrimRight(data[secOffset:secOffset+8], "\x00"))
		sec := Section{
			Name:            name,
			VirtualSize:     binary.LittleEndian.Uint32(data[secOffset+8 : secOffset+12]),
			VirtualAddress:  binary.LittleEndian.Uint32(data[secOffset+12 : secOffset+16]),
			RawSize:         binary.LittleEndian.Uint32(data[secOffset+16 : secOffset+20]),
			RawOffset:       binary.LittleEndian.Uint32(data[secOffset+20 : secOffset+24]),
			Characteristics: binary.LittleEndian.Uint32(data[secOffset+36 : secOffset+40]),
		}

		// Calculate entropy
		if sec.RawSize > 0 && int(sec.RawOffset)+int(sec.RawSize) <= len(data) {
			sec.Entropy = calculateEntropy(data[sec.RawOffset : sec.RawOffset+sec.RawSize])
		}

		// Check for suspicious sections
		sec.Suspicious, sec.Reason = checkSuspiciousSection(sec)

		sections = append(sections, sec)
	}

	return sections
}

// checkSuspiciousSection checks if a section is suspicious.
func checkSuspiciousSection(sec Section) (bool, string) {
	suspiciousNames := map[string]string{
		"UPX0":   "UPX packer section",
		"UPX1":   "UPX packer section",
		".vmp0":  "VMProtect packer section",
		".vmp1":  "VMProtect packer section",
		".themida": "Themida packer section",
		".enigma1": "Enigma packer section",
		".enigma2": "Enigma packer section",
		".adata":  "AsProtect packer section",
	}

	if reason, ok := suspiciousNames[sec.Name]; ok {
		return true, reason
	}

	// Check for writable + executable sections (W^X violation)
	if sec.Characteristics&0x80000000 != 0 && sec.Characteristics&0x20000000 != 0 {
		return true, "Writable and executable section (W^X violation)"
	}

	// Check for unusually high entropy (packed/encrypted)
	if sec.Entropy > 7.5 && sec.RawSize > 1024 {
		return true, fmt.Sprintf("High entropy section (%.2f) - likely packed or encrypted", sec.Entropy)
	}

	// Check for empty name or suspicious names
	if sec.Name == "" || sec.Name == "\x00\x00\x00\x00\x00\x00\x00\x00" {
		return true, "Empty section name"
	}

	return false, ""
}

// parseImports parses PE import table.
func parseImports(data []byte, bits int) ([]string, []string) {
	var imports []string
	var dlls []string

	// Find import directory (Data Directory entry 1)
	peOffset := binary.LittleEndian.Uint32(data[0x3C:0x40])
	coffOffset := peOffset + 4
	optOffset := coffOffset + 20
	magic := binary.LittleEndian.Uint16(data[optOffset : optOffset+2])

	var importDirOffset uint32
	if magic == 0x10B {
		importDirOffset = optOffset + 96 + 8
	} else if magic == 0x20B {
		importDirOffset = optOffset + 112 + 8
	}

	if int(importDirOffset)+8 > len(data) {
		return imports, dlls
	}

	importRVA := binary.LittleEndian.Uint32(data[importDirOffset : importDirOffset+4])
	importSize := binary.LittleEndian.Uint32(data[importDirOffset+4 : importDirOffset+8])

	if importRVA == 0 || importSize == 0 {
		return imports, dlls
	}

	// Simple heuristic: look for import-like patterns in the binary
	// This is a simplified approach since full import parsing requires RVA resolution
	lookForDLLImports(data, &imports, &dlls)

	return imports, dlls
}

// lookForDLLImports does a heuristic search for common DLL imports.
func lookForDLLImports(data []byte, imports *[]string, dlls *[]string) {
	knownDLLs := []string{
		"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
		"ws2_32.dll", "wininet.dll", "urlmon.dll", "shell32.dll",
		"ole32.dll", "oleaut32.dll", "msvcrt.dll", "crypt32.dll",
		"bcrypt.dll", "winhttp.dll", "wldap32.dll", "netapi32.dll",
	}

	knownImports := []string{
		"VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
		"CreateRemoteThread", "NtUnmapViewOfSection", "SetWindowsHookEx",
		"OpenProcess", "ReadProcessMemory", "WriteProcessMemory",
		"CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
		"URLDownloadToFileA", "URLDownloadToFileW",
		"InternetOpenA", "InternetOpenW", "HttpSendRequestA",
		"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
		"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
		"NtQueryInformationProcess", "OutputDebugStringA",
		"GetTickCount", "QueryPerformanceCounter",
		"LoadLibraryA", "LoadLibraryW", "GetProcAddress",
	}

	dataStr := string(data)

	// Check for DLLs
	for _, dll := range knownDLLs {
		if strings.Contains(strings.ToLower(dataStr), dll) {
			*dlls = append(*dlls, dll)
		}
	}

	// Check for imports (simplified - just check if function name appears)
	for _, imp := range knownImports {
		if strings.Contains(dataStr, imp) {
			*imports = append(*imports, imp)
		}
	}
}

// checkTLS checks for TLS directory and callbacks.
func checkTLS(data []byte, bits int) *TLSInfo {
	tls := &TLSInfo{}

	// Look for TLS-related patterns
	// TLS callbacks are commonly used by malware for anti-debugging
	dataStr := string(data)
	if strings.Contains(dataStr, "TLS") || strings.Contains(dataStr, "tls") {
		tls.HasCallbacks = true
	}

	return tls
}

// checkDebug checks for debug information.
func checkDebug(data []byte, bits int) *DebugInfo {
	info := &DebugInfo{}

	// Look for PDB path
	dataStr := string(data)
	if strings.Contains(dataStr, ".pdb") {
		info.HasDebug = true
		info.DebugType = "PDB"
		
		// Try to extract PDB path
		idx := strings.Index(dataStr, ".pdb")
		if idx > 0 {
			start := idx
			for start > 0 && dataStr[start-1] != 0 {
				start--
			}
			if start < idx {
				info.PDBPath = dataStr[start : idx+4]
			}
		}
	}

	return info
}

// parseResources parses PE resources (simplified).
func parseResources(data []byte, bits int) []Resource {
	var resources []Resource

	// Look for common resource types
	resourceTypes := map[string][]byte{
		"RT_ICON":       {0x03, 0x00, 0x00, 0x00},
		"RT_BITMAP":     {0x02, 0x00, 0x00, 0x00},
		"RT_STRING":     {0x06, 0x00, 0x00, 0x00},
		"RT_MANIFEST":   {0x18, 0x00, 0x00, 0x00},
		"RT_VERSION":    {0x10, 0x00, 0x00, 0x00},
	}

	for resType, sig := range resourceTypes {
		if bytes.Contains(data, sig) {
			resources = append(resources, Resource{
				Type: resType,
			})
		}
	}

	return resources
}

// parseRichHeader parses the Rich header if present.
func parseRichHeader(data []byte) *RichHeader {
	// Rich header is located between DOS stub and PE signature
	peOffset := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if peOffset < 0x80 {
		return nil
	}

	// Look for "Rich" marker
	richMarker := []byte("Rich")
	for i := 0x80; i < int(peOffset)-4; i++ {
		if bytes.Equal(data[i:i+4], richMarker) {
			// Found Rich header
			rich := &RichHeader{}
			if i+8 <= len(data) {
				rich.CompID = binary.LittleEndian.Uint32(data[i+4 : i+8])
			}
			return rich
		}
	}

	return nil
}

// parseDataDirs parses PE data directories.
func parseDataDirs(data []byte, optOffset uint32, magic uint16) []DataDir {
	var dirs []DataDir

	dirNames := []string{
		"Export", "Import", "Resource", "Exception", "Certificate",
		"Base Relocation", "Debug", "Architecture", "Global Ptr",
		"TLS", "Load Config", "Bound Import", "IAT", "Delay Import",
		"CLR Runtime Header", "Reserved",
	}

	// Data directories start after standard optional header fields
	var dirStart uint32
	if magic == 0x10B {
		dirStart = optOffset + 96
	} else if magic == 0x20B {
		dirStart = optOffset + 112
	}

	for i := 0; i < 16; i++ {
		dirOffset := dirStart + uint32(i*8)
		if int(dirOffset)+8 > len(data) {
			break
		}

		rva := binary.LittleEndian.Uint32(data[dirOffset : dirOffset+4])
		size := binary.LittleEndian.Uint32(data[dirOffset+4 : dirOffset+8])

		if rva != 0 || size != 0 {
			dirs = append(dirs, DataDir{
				Name: dirNames[i],
				RVA:  rva,
				Size: size,
			})
		}
	}

	return dirs
}

// calculateEntropy calculates Shannon entropy of data.
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	size := float64(len(data))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / size
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// machineName returns the string name for a PE machine type.
func machineName(machine uint16) string {
	names := map[uint16]string{
		0x014C: "x86 (32-bit)",
		0x0200: "Intel Itanium (IA-64)",
		0x8664: "x86-64 (64-bit)",
		0x01C0: "ARM (Thumb-2)",
		0x01C4: "ARM Little-Endian",
		0xAA64: "ARM64 (AArch64)",
		0x0EBC: "EFI Byte Code",
		0x01F0: "PowerPC Little-Endian",
		0x01F1: "PowerPC with floating point",
		0x0166: "MIPS R4000 Little-Endian",
		0x01A2: "Hitachi SH3",
		0x01A6: "Hitachi SH4",
		0x01C2: "ARM or Thumb (interworking)",
		0x01D3: "Matsushita AM33",
	}

	if name, ok := names[machine]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04X)", machine)
}

// subsystemName returns the string name for a PE subsystem.
func subsystemName(subsystem uint16) string {
	names := map[uint16]string{
		0:  "Unknown",
		1:  "Native",
		2:  "Windows GUI",
		3:  "Windows Console",
		5:  "OS/2 Console",
		7:  "POSIX Console",
		9:  "Windows CE",
		10: "EFI Application",
		11: "EFI Boot Service Driver",
		12: "EFI Runtime Driver",
		13: "EFI ROM",
		14: "Xbox",
		16: "Windows Boot Application",
	}

	if name, ok := names[subsystem]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", subsystem)
}
