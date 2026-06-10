package office

import (
	"bytes"
	"fmt"
	"strings"
)

// Result holds office macro analysis results.
type Result struct {
	FileName   string         `json:"file_name"`
	Format     string         `json:"format,omitempty"`     // "ooxml" or "ole2"
	Type       string         `json:"type,omitempty"`       // "docx"/"xlsx"/"pptx" for OOXML
	HasMacros  bool           `json:"has_macros"`
	MacroCount int            `json:"macro_count"`
	AutoExec   []string       `json:"auto_exec,omitempty"`
	Suspicious []string       `json:"suspicious,omitempty"`
	App        string         `json:"app,omitempty"`
	Metadata   *OOXMLDocument `json:"metadata,omitempty"`
}

var autoExecPatterns = []string{
	"AutoOpen", "Auto_Open", "AutoClose", "Auto_Close",
	"AutoExec", "Auto_Exec", "Workbook_Open", "Workbook_BeforeClose",
	"Document_Open", "Document_Close", "AutoOpenDocument",
}

var suspiciousKeywords = []string{
	"Shell", "CreateObject", "WScript", "Shell.Application",
	"ADODB.Stream", "WinHttp", "MSXML2", "URLDownloadToFile",
	"Process.Start", "cmd.exe", "powershell", "regsvr32",
	"rundll32", "mshta", "certutil", "bitsadmin", "wmic",
	"cscript", "wscript", "Base64Decode", "Socket", "TCP",
	".exe", ".dll", ".vbs", ".ps1", ".bat", ".scr",
	"GetObject", "Eval", "Execute", "ExecuteGlobal",
	"CallByName", "Chr(", "ChrW(",
}

// Analyze detects VBA macros in OLE2 documents and extracts metadata from OOXML documents.
func Analyze(data []byte, fileName string) *Result {
	result := &Result{
		FileName: fileName,
	}

	if len(data) < 512 {
		return result
	}

	// OOXML (ZIP) takes precedence: the analyzer extracts metadata and skips macro detection
	// (macros in OOXML are stored in vbaProject.bin, not as OLE2 streams).
	if ooxmlType := DetectOOXMLBytes(data); ooxmlType != "" {
		result.Format = "ooxml"
		result.Type = ooxmlType
		doc, err := ExtractOOXMLFromBytes(data)
		if err == nil && doc != nil {
			result.Metadata = doc
			result.App = ooxmlAppName(ooxmlType)
		}
		return result
	}

	// Check for OLE2 magic
	if !isOLE2(data) {
		return result
	}
	result.Format = "ole2"

	// Parse directory structure
	streams := extractOLE2Streams(data)
	if len(streams) == 0 {
		return result
	}

	// Check for VBA project streams
	vbaStreams := []string{"VBA/", "_VBA_PROJECT", "ThisDocument", "ThisWorkbook"}
	for _, stream := range streams {
		for _, vba := range vbaStreams {
			if strings.Contains(stream, vba) {
				result.HasMacros = true
				break
			}
		}
	}

	if !result.HasMacros {
		return result
	}

	// Count macro modules
	for _, stream := range streams {
		if strings.HasPrefix(stream, "Module") || strings.HasPrefix(stream, "Class") || stream == "ThisDocument" || stream == "ThisWorkbook" {
			result.MacroCount++
		}
	}

	// Check for auto-exec patterns
	macroContent := extractMacroContent(data)
	for _, pattern := range autoExecPatterns {
		if strings.Contains(macroContent, pattern) {
			result.AutoExec = append(result.AutoExec, pattern)
		}
	}

	// Check for suspicious keywords
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(macroContent, keyword) {
			result.Suspicious = append(result.Suspicious, keyword)
		}
	}

	// Detect application
	result.App = detectApp(streams)

	return result
}

func isOLE2(data []byte) bool {
	ole2Sig := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	return bytes.HasPrefix(data, ole2Sig)
}

func extractOLE2Streams(data []byte) []string {
	var streams []string

	// Simple stream name extraction
	for i := 0; i < len(data)-64; i += 64 {
		if data[i] != 0 {
			end := i
			for end < len(data) && data[end] != 0 && end-i < 32 {
				end++
			}
			if end > i {
				streams = append(streams, string(data[i:end]))
			}
		}
	}

	return streams
}

func extractMacroContent(data []byte) string {
	// Extract text content from OLE2 streams
	var content []byte
	for i := 0; i < len(data)-1; i++ {
		if data[i] >= 0x20 && data[i] <= 0x7E {
			content = append(content, data[i])
		}
	}
	return string(content)
}

func detectApp(streams []string) string {
	for _, stream := range streams {
		if strings.Contains(stream, "Word") {
			return "Microsoft Word"
		}
		if strings.Contains(stream, "Excel") {
			return "Microsoft Excel"
		}
		if strings.Contains(stream, "PowerPoint") {
			return "Microsoft PowerPoint"
		}
		if strings.Contains(stream, "Outlook") {
			return "Microsoft Outlook"
		}
	}
	return "Microsoft Office"
}

// ooxmlAppName maps an OOXML type code to a human-readable application name.
func ooxmlAppName(t string) string {
	switch t {
	case "docx":
		return "Microsoft Word"
	case "xlsx":
		return "Microsoft Excel"
	case "pptx":
		return "Microsoft PowerPoint"
	default:
		return "Microsoft Office"
	}
}

// Print displays office analysis results.
func Print(r *Result) {
	fmt.Println()
	if r.Metadata != nil {
		fmt.Printf("  Office OOXML Analysis: %s\n", r.FileName)
		fmt.Println(FormatOOXML(r.Metadata))
		return
	}
	if r.HasMacros {
		fmt.Printf("  Office Macro Analysis: %s\n", r.FileName)
		fmt.Printf("  Application: %s\n", r.App)
		fmt.Printf("  Macros Found: %d\n", r.MacroCount)
		fmt.Println()

		if len(r.AutoExec) > 0 {
			fmt.Println("  ⚠  Auto-Exec Patterns:")
			for _, p := range r.AutoExec {
				fmt.Printf("    %s\n", p)
			}
		}

		if len(r.Suspicious) > 0 {
			fmt.Println()
			fmt.Println("  ⚠  Suspicious Keywords:")
			for _, s := range r.Suspicious {
				fmt.Printf("    %s\n", s)
			}
		}
	} else {
		fmt.Printf("  No macros detected: %s\n", r.FileName)
	}
	fmt.Println()
}
