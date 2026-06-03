package packing

import (
	"bytes"
	"math"
)

// Result holds packing detection results.
type Result struct {
	Detected   bool     `json:"detected"`
	Packer     string   `json:"packer,omitempty"`
	Confidence float64  `json:"confidence"`
	Signatures []string `json:"signatures,omitempty"`
	Indicators []string `json:"indicators,omitempty"`
}

// KnownPacker represents a known packing signature.
type KnownPacker struct {
	Name     string
	Magic    []byte
	Sections []string
	Imports  []string
}

// knownPackers is a list of known packers and their signatures.
var knownPackers = []KnownPacker{
	{
		Name:  "UPX",
		Magic: []byte("UPX!"),
		Sections: []string{
			"UPX0", "UPX1", "UPX2",
		},
	},
	{
		Name:  "VMProtect",
		Magic: []byte{0xE8, 0x00, 0x00, 0x00, 0x00},
		Sections: []string{
			".vmp0", ".vmp1", ".vmp2",
		},
	},
	{
		Name:  "Themida",
		Sections: []string{
			".themida", ".winlice",
		},
	},
	{
		Name:  "ASPack",
		Sections: []string{
			".adata", ".aspack",
		},
	},
	{
		Name:  "PECompact",
		Sections: []string{
			".PEC2", ".pec1", ".PEC2MO",
		},
	},
	{
		Name:  "Armadillo",
		Sections: []string{
			".armadillo", ".clon",
		},
	},
	{
		Name:  "Enigma Protector",
		Sections: []string{
			".enigma1", ".enigma2",
		},
	},
	{
		Name:  "MPRESS",
		Sections: []string{
			".MPRESS1", ".MPRESS2",
		},
	},
	{
		Name:  "MEW",
		Sections: []string{
			"MEW",
		},
	},
	{
		Name:  "FSG",
		Sections: []string{
			"FSG!2",
		},
	},
	{
		Name:  "NsPack",
		Sections: []string{
			".nsp0", ".nsp1", ".nsp2",
		},
	},
	{
		Name:  "Petite",
		Sections: []string{
			".petite",
		},
	},
	{
		Name:  "Y0da Protector",
		Sections: []string{
			".y0da",
		},
	},
	{
		Name:  "PKLite",
		Sections: []string{
			".PKL32", ".PKL",
		},
	},
	{
		Name:  "LZEXE",
		Sections: []string{
			"lzexe",
		},
	},
}

// Detect performs packing detection on executable data.
func Detect(data []byte, format string) *Result {
	result := &Result{
		Confidence: 0,
	}

	if len(data) < 100 {
		return result
	}

	// Check for known packer signatures
	for _, packer := range knownPackers {
		score := 0.0
		var indicators []string

		// Check magic bytes
		if len(packer.Magic) > 0 && bytes.Contains(data, packer.Magic) {
			score += 0.8
			indicators = append(indicators, "Magic bytes match")
		}

		// Check section names (PE format)
		if format == "PE" {
			for _, section := range packer.Sections {
				sectionBytes := []byte(section)
				if bytes.Contains(data, sectionBytes) {
					score += 0.6
					indicators = append(indicators, "Section name: "+section)
					break
				}
			}
		}

		// If we have a strong match
		if score >= 0.6 {
			if !result.Detected || score > result.Confidence {
				result.Detected = true
				result.Packer = packer.Name
				result.Confidence = math.Min(score, 0.95)
				result.Signatures = packer.Sections
				result.Indicators = indicators
			}
		}
	}

	// Additional heuristic checks
	if !result.Detected {
		heurResult := heuristicDetection(data)
		if heurResult.Detected && heurResult.Confidence > result.Confidence {
			result = heurResult
		}
	}

	return result
}

// heuristicDetection uses heuristics to detect packing.
func heuristicDetection(data []byte) *Result {
	result := &Result{}

	// Check for high entropy in code sections (indicates encryption)
	codeSections := findCodeSections(data)
	if len(codeSections) > 0 {
		for _, section := range codeSections {
			entropy := calculateEntropy(section.Data)
			if entropy > 7.0 {
				result.Indicators = append(result.Indicators,
					"High entropy in code section (%.2f)")
				result.Confidence += 0.3
			}
		}
	}

	// Check for unusual import patterns
	if hasUnusualImports(data) {
		result.Indicators = append(result.Indicators, "Unusual import patterns")
		result.Confidence += 0.2
	}

	// Check for anti-debugging techniques
	if hasAntiDebug(data) {
		result.Indicators = append(result.Indicators, "Anti-debugging techniques detected")
		result.Confidence += 0.3
	}

	// Check for code obfuscation patterns
	if hasObfuscation(data) {
		result.Indicators = append(result.Indicators, "Code obfuscation patterns")
		result.Confidence += 0.2
	}

	if result.Confidence >= 0.4 {
		result.Detected = true
		result.Packer = "Unknown (heuristic)"
		result.Confidence = math.Min(result.Confidence, 0.7)
	}

	return result
}

// CodeSection represents a code section for analysis.
type CodeSection struct {
	Offset int
	Size   int
	Data   []byte
}

// findCodeSections finds potential code sections in the binary.
func findCodeSections(data []byte) []CodeSection {
	var sections []CodeSection

	// Simple heuristic: look for common code patterns
	// This is a simplified approach
	for i := 0; i < len(data)-100; i++ {
		// Look for function prologues (x86: push ebp; mov ebp, esp)
		if data[i] == 0x55 && i+2 < len(data) && data[i+1] == 0x8B && data[i+2] == 0xEC {
			sections = append(sections, CodeSection{
				Offset: i,
				Size:   256,
				Data:   data[i:min(i+256, len(data))],
			})
		}
	}

	// Return at most 10 sections
	if len(sections) > 10 {
		sections = sections[:10]
	}

	return sections
}

// hasUnusualImports checks for unusual import patterns.
func hasUnusualImports(data []byte) bool {
	dataStr := string(data)
	unusualPatterns := []string{
		"GetTickCount", "QueryPerformanceCounter",
		"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
		"NtQueryInformationProcess",
		"OutputDebugString",
	}

	count := 0
	for _, pattern := range unusualPatterns {
		if bytes.Contains(data, []byte(pattern)) {
			count++
		}
	}

	return count >= 3
}

// hasAntiDebug checks for anti-debugging techniques.
func hasAntiDebug(data []byte) bool {
	antiDebugPatterns := []string{
		"IsDebuggerPresent",
		"CheckRemoteDebuggerPresent",
		"NtQueryInformationProcess",
		"ZwQueryInformationProcess",
		"GetTickCount",
		"QueryPerformanceCounter",
		"rdtsc",
	}

	dataStr := string(data)
	count := 0
	for _, pattern := range antiDebugPatterns {
		if bytes.Contains(data, []byte(pattern)) {
			count++
		}
	}

	return count >= 2
}

// hasObfuscation checks for code obfuscation patterns.
func hasObfuscation(data []byte) bool {
	// Check for high concentration of jumps (possible junk code)
	jmpCount := 0
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0xEB || data[i] == 0xE9 { // JMP short/near
			jmpCount++
		}
	}

	// If more than 5% of bytes are jumps, likely obfuscated
	threshold := float64(len(data)) * 0.05
	return float64(jmpCount) > threshold
}

// calculateEntropy calculates Shannon entropy.
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
