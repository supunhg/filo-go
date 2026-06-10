package office

import (
	"archive/zip"
	"bytes"
	"testing"
)

// buildOLE2WithMacros synthesizes a minimal OLE2-looking blob that the existing
// macro detector will classify as containing macros. The OLE2 magic at the
// start is enough to pass isOLE2(), and the embedded strings ("VBA/",
// "ThisDocument", "Module1") trigger the VBA stream detection. Auto-exec and
// suspicious keywords are embedded as printable ASCII so the keyword scan
// picks them up.
func buildOLE2WithMacros(t *testing.T, autoExec, suspicious []string) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	// OLE2 magic
	copy(buf[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})

	// Place VBA stream names at known offsets so extractOLE2Streams picks them up.
	copy(buf[64:64+len("VBA/")], "VBA/")
	copy(buf[128:128+len("ThisDocument")], "ThisDocument")
	copy(buf[192:192+len("Module1")], "Module1")

	// Embed VBA-style content (printable ASCII) so keyword/auto-exec scans fire.
	off := 300
	for _, s := range append(append([]string{}, autoExec...), suspicious...) {
		copy(buf[off:], s)
		off += len(s) + 8
	}
	return buf
}

// buildOOXMLWithVBA creates an in-memory OOXML zip that contains both the
// docProps metadata and an embedded vbaProject.bin (synthesized OLE2 bytes).
func buildOOXMLWithVBA(t *testing.T, ooxmlType string, vbaBytes []byte) []byte {
	t.Helper()
	ct, main, props := ooxmlFixtureTriple(ooxmlType)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"[Content_Types].xml": ct,
		main:                  props,
		"docProps/core.xml":   coreFull,
	} {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	var vbaPath string
	switch ooxmlType {
	case "docx":
		vbaPath = "word/vbaProject.bin"
	case "xlsx":
		vbaPath = "xl/vbaProject.bin"
	case "pptx":
		vbaPath = "ppt/vbaProject.bin"
	default:
		vbaPath = "word/vbaProject.bin"
	}
	f, err := w.Create(vbaPath)
	if err != nil {
		t.Fatalf("zip create %s: %v", vbaPath, err)
	}
	if _, err := f.Write(vbaBytes); err != nil {
		t.Fatalf("zip write vba: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// ooxmlFixtureTriple returns the [Content_Types].xml, main part path, and a
// minimal main-part XML for the given OOXML type.
func ooxmlFixtureTriple(ooxmlType string) (ct, main, props string) {
	switch ooxmlType {
	case "docx":
		return docxCT, "word/document.xml", "<w:document/>"
	case "xlsx":
		return xlsxCT, "xl/workbook.xml", "<workbook/>"
	case "pptx":
		return pptxCT, "ppt/presentation.xml", "<presentation/>"
	}
	return "", "", ""
}

func TestExtractVBAProjectBytesNoOOXML(t *testing.T) {
	if got := ExtractVBAProjectBytes([]byte("not a zip")); got != nil {
		t.Errorf("expected nil for non-OOXML input, got %d bytes", len(got))
	}
}

func TestExtractVBAProjectBytesNoVBA(t *testing.T) {
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": docxCT,
		"word/document.xml":   "<w:document/>",
		"docProps/core.xml":   coreFull,
	})
	if got := ExtractVBAProjectBytes(data); got != nil {
		t.Errorf("expected nil for OOXML without vbaProject.bin, got %d bytes", len(got))
	}
}

func TestExtractVBAProjectBytesDOCX(t *testing.T) {
	vba := buildOLE2WithMacros(t, []string{"AutoOpen"}, []string{"Shell"})
	data := buildOOXMLWithVBA(t, "docx", vba)
	got := ExtractVBAProjectBytes(data)
	if got == nil {
		t.Fatal("expected vbaProject.bin bytes, got nil")
	}
	if len(got) == 0 {
		t.Fatal("expected non-empty vbaProject.bin")
	}
}

func TestExtractVBAProjectBytesXLSX(t *testing.T) {
	vba := buildOLE2WithMacros(t, nil, nil)
	data := buildOOXMLWithVBA(t, "xlsx", vba)
	got := ExtractVBAProjectBytes(data)
	if got == nil {
		t.Fatal("expected vbaProject.bin bytes for xlsx, got nil")
	}
}

func TestExtractVBAProjectBytesPPTX(t *testing.T) {
	vba := buildOLE2WithMacros(t, nil, nil)
	data := buildOOXMLWithVBA(t, "pptx", vba)
	got := ExtractVBAProjectBytes(data)
	if got == nil {
		t.Fatal("expected vbaProject.bin bytes for pptx, got nil")
	}
}

func TestExtractVBAProjectBytesBadZipEntry(t *testing.T) {
	// A vbaProject.bin entry with corrupted content - ExtractVBAProjectBytes
	// should still return whatever it can read. We just verify no panic.
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": docxCT,
		"word/document.xml":   "<w:document/>",
		"word/vbaProject.bin": "not-actually-ole2-but-present",
		"docProps/core.xml":   coreFull,
	})
	got := ExtractVBAProjectBytes(data)
	if got == nil {
		t.Error("expected vbaProject.bin bytes, got nil")
	}
}

func TestAnalyzeOOXMLWithVBAMacros(t *testing.T) {
	vba := buildOLE2WithMacros(t,
		[]string{"AutoOpen", "Document_Open"},
		[]string{"Shell", "cmd.exe", "powershell"})
	data := buildOOXMLWithVBA(t, "docx", vba)

	r := Analyze(data, "macro_doc.docx")
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Format != "ooxml" {
		t.Errorf("expected Format=ooxml, got %q", r.Format)
	}
	if r.Type != "docx" {
		t.Errorf("expected Type=docx, got %q", r.Type)
	}
	if !r.HasMacros {
		t.Error("expected HasMacros=true for OOXML with embedded vbaProject.bin")
	}
	if r.MacroCount == 0 {
		t.Error("expected MacroCount > 0")
	}
	if len(r.AutoExec) == 0 {
		t.Error("expected at least one auto-exec pattern detected")
	}
	if len(r.Suspicious) == 0 {
		t.Error("expected at least one suspicious keyword detected")
	}
	if r.Metadata == nil {
		t.Error("expected Metadata to be set for OOXML with vbaProject.bin")
	}
}

func TestAnalyzeOOXMLWithoutVBAMacros(t *testing.T) {
	// OOXML with no vbaProject.bin - HasMacros should be false
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": docxCT,
		"word/document.xml":   "<w:document/>",
		"docProps/core.xml":   coreFull,
	})
	r := Analyze(data, "clean.docx")
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.HasMacros {
		t.Error("expected HasMacros=false for OOXML without vbaProject.bin")
	}
	if r.MacroCount != 0 {
		t.Errorf("expected MacroCount=0, got %d", r.MacroCount)
	}
	if r.Metadata == nil {
		t.Error("expected Metadata to be set")
	}
}

func TestAnalyzeOOXLXVBA(t *testing.T) {
	vba := buildOLE2WithMacros(t,
		[]string{"Workbook_Open"},
		[]string{"CreateObject"})
	data := buildOOXMLWithVBA(t, "xlsx", vba)
	r := Analyze(data, "macro_sheet.xlsx")
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Type != "xlsx" {
		t.Errorf("expected Type=xlsx, got %q", r.Type)
	}
	if !r.HasMacros {
		t.Error("expected HasMacros=true for xlsx with vbaProject.bin")
	}
}

func TestAnalyzeMergeMacroFieldsAppOverride(t *testing.T) {
	// When the OOXML app name is "Microsoft Word" (from ooxmlAppName) and the
	// embedded VBA carries the same name, the merge should keep the OOXML app
	// (not overwrite with an empty value).
	vba := buildOLE2WithMacros(t, nil, nil)
	data := buildOOXMLWithVBA(t, "docx", vba)
	r := Analyze(data, "doc.docx")
	if r.App != "Microsoft Word" {
		t.Errorf("expected App='Microsoft Word', got %q", r.App)
	}
}

func TestMergeMacroFieldsNilSrc(t *testing.T) {
	dst := &Result{App: "existing"}
	mergeMacroFields(dst, nil)
	if dst.App != "existing" {
		t.Errorf("expected dst unchanged for nil src, got App=%q", dst.App)
	}
}

func TestMergeMacroFieldsCopiesAllFields(t *testing.T) {
	dst := &Result{Format: "ooxml", App: "Microsoft Word"}
	src := &Result{
		HasMacros:  true,
		MacroCount: 3,
		AutoExec:   []string{"AutoOpen"},
		Suspicious: []string{"Shell"},
	}
	mergeMacroFields(dst, src)
	if !dst.HasMacros {
		t.Error("expected HasMacros copied")
	}
	if dst.MacroCount != 3 {
		t.Errorf("expected MacroCount=3, got %d", dst.MacroCount)
	}
	if len(dst.AutoExec) != 1 || dst.AutoExec[0] != "AutoOpen" {
		t.Errorf("AutoExec not copied correctly: %v", dst.AutoExec)
	}
	if len(dst.Suspicious) != 1 || dst.Suspicious[0] != "Shell" {
		t.Errorf("Suspicious not copied correctly: %v", dst.Suspicious)
	}
	if dst.App != "Microsoft Word" {
		t.Errorf("expected App unchanged, got %q", dst.App)
	}
}

func TestAnalyzeOLE2VBAStandalone(t *testing.T) {
	// Test the helper directly with a synthesized OLE2 buffer
	ole2 := buildOLE2WithMacros(t,
		[]string{"Auto_Open"},
		[]string{"WScript", "CreateObject"})
	r := analyzeOLE2VBA(ole2, "legacy.doc")
	if !r.HasMacros {
		t.Error("expected HasMacros=true")
	}
	if r.MacroCount == 0 {
		t.Error("expected MacroCount > 0")
	}
}

func TestAnalyzeOLE2VBAEmpty(t *testing.T) {
	// Empty OLE2 buffer - should return result with no macros
	r := analyzeOLE2VBA(make([]byte, 4096), "empty.doc")
	if r.HasMacros {
		t.Error("expected HasMacros=false for empty OLE2")
	}
}

func TestPrintOOXMLWithMacros(t *testing.T) {
	// Verify Print doesn't panic when both metadata and macros are present
	vba := buildOLE2WithMacros(t, []string{"AutoOpen"}, []string{"Shell"})
	data := buildOOXMLWithVBA(t, "docx", vba)
	r := Analyze(data, "macro.docx")
	// Just ensure no panic - Print writes to stdout
	Print(r)
}
