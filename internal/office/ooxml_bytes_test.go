package office

import (
	"archive/zip"
	"bytes"
	"testing"
)

// buildZip returns an in-memory zip archive with the given entries (name -> content).
func buildZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

const (
	docxCT  = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
</Types>`

	xlsxCT = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`

	pptxCT = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`

	coreFull = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <cp:revision>3</cp:revision>
  <dc:creator>Jane Doe</dc:creator>
  <dcterms:created xsi:type="dcterms:W3CDTF">2024-01-15T10:30:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2024-02-20T14:45:00Z</dcterms:modified>
  <dc:title>Quarterly Report</dc:title>
  <dc:subject>Financial Analysis</dc:subject>
  <dc:description>Confidential report</dc:description>
  <cp:keywords>finance, Q1, 2024</cp:keywords>
  <cp:category>Reports</cp:category>
  <cp:lastModifiedBy>John Smith</cp:lastModifiedBy>
  <cp:contentStatus>Final</cp:contentStatus>
  <cp:version>2.1</cp:version>
</coreProperties>`

	appFull = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <AppVersion>16.0000</AppVersion>
  <Company>Acme Corp</Company>
  <Template>Normal.dotm</Template>
  <TotalTime>120</TotalTime>
  <Pages>15</Pages>
  <Words>4500</Words>
  <Characters>27000</Characters>
  <Lines>200</Lines>
  <Paragraphs>50</Paragraphs>
  <DocSecurity>0</DocSecurity>
</Properties>`

	customFull = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Classification">
    <vt:lpwstr>Top Secret</vt:lpwstr>
  </property>
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="3" name="Reviewer">
    <vt:lpwstr>Alice</vt:lpwstr>
  </property>
</Properties>`
)

func TestDetectOOXMLBytesTooSmall(t *testing.T) {
	if got := DetectOOXMLBytes([]byte{0x50, 0x4B}); got != "" {
		t.Errorf("expected empty for <4 bytes, got %q", got)
	}
}

func TestDetectOOXMLBytesNotZip(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}
	if got := DetectOOXMLBytes(data); got != "" {
		t.Errorf("expected empty for non-zip, got %q", got)
	}
}

func TestDetectOOXMLBytesBadZip(t *testing.T) {
	// Valid PK\x03\x04 magic but garbage afterwards
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0xFF, 0xFF, 0xFF, 0xFF}
	if got := DetectOOXMLBytes(data); got != "" {
		t.Errorf("expected empty for malformed zip, got %q", got)
	}
}

func TestDetectOOXMLBytesDOCX(t *testing.T) {
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": docxCT,
		"word/document.xml":   "<w:document/>",
	})
	if got := DetectOOXMLBytes(data); got != "docx" {
		t.Errorf("expected 'docx', got %q", got)
	}
}

func TestDetectOOXMLBytesXLSX(t *testing.T) {
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": xlsxCT,
		"xl/workbook.xml":     "<workbook/>",
	})
	if got := DetectOOXMLBytes(data); got != "xlsx" {
		t.Errorf("expected 'xlsx', got %q", got)
	}
}

func TestDetectOOXMLBytesPPTX(t *testing.T) {
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": pptxCT,
		"ppt/presentation.xml": "<presentation/>",
	})
	if got := DetectOOXMLBytes(data); got != "pptx" {
		t.Errorf("expected 'pptx', got %q", got)
	}
}

func TestDetectOOXMLBytesUnknownType(t *testing.T) {
	ct := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>`
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": ct,
	})
	if got := DetectOOXMLBytes(data); got != "" {
		t.Errorf("expected empty for unknown OOXML type, got %q", got)
	}
}

func TestExtractOOXMLFromBytesNotOOXML(t *testing.T) {
	_, err := ExtractOOXMLFromBytes([]byte("not a zip"))
	if err == nil {
		t.Fatal("expected error for non-zip input")
	}
}

func TestExtractOOXMLFromBytesDOCXFull(t *testing.T) {
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": docxCT,
		"word/document.xml":   "<w:document/>",
		"docProps/core.xml":   coreFull,
		"docProps/app.xml":    appFull,
		"docProps/custom.xml": customFull,
	})
	doc, err := ExtractOOXMLFromBytes(data)
	if err != nil {
		t.Fatalf("ExtractOOXMLFromBytes: %v", err)
	}
	if doc.Type != "docx" {
		t.Errorf("expected type=docx, got %q", doc.Type)
	}
	if doc.Author != "Jane Doe" {
		t.Errorf("expected Author='Jane Doe', got %q", doc.Author)
	}
	if doc.Title != "Quarterly Report" {
		t.Errorf("expected Title='Quarterly Report', got %q", doc.Title)
	}
	if doc.Subject != "Financial Analysis" {
		t.Errorf("expected Subject='Financial Analysis', got %q", doc.Subject)
	}
	if doc.Keywords != "finance, Q1, 2024" {
		t.Errorf("expected Keywords='finance, Q1, 2024', got %q", doc.Keywords)
	}
	if doc.Category != "Reports" {
		t.Errorf("expected Category='Reports', got %q", doc.Category)
	}
	if doc.Comments != "Confidential report" {
		t.Errorf("expected Comments='Confidential report', got %q", doc.Comments)
	}
	if doc.LastSavedBy != "John Smith" {
		t.Errorf("expected LastSavedBy='John Smith', got %q", doc.LastSavedBy)
	}
	if doc.Revision != "3" {
		t.Errorf("expected Revision='3', got %q", doc.Revision)
	}
	if doc.Version != "2.1" {
		t.Errorf("expected Version='2.1', got %q", doc.Version)
	}
	if doc.Created.IsZero() {
		t.Error("expected Created to be non-zero")
	}
	if doc.Modified.IsZero() {
		t.Error("expected Modified to be non-zero")
	}
	// Custom props from app.xml
	if doc.CustomProps["Company"] != "Acme Corp" {
		t.Errorf("expected Company='Acme Corp', got %q", doc.CustomProps["Company"])
	}
	if doc.CustomProps["Template"] != "Normal.dotm" {
		t.Errorf("expected Template='Normal.dotm', got %q", doc.CustomProps["Template"])
	}
	if doc.CustomProps["Pages"] != "15" {
		t.Errorf("expected Pages='15', got %q", doc.CustomProps["Pages"])
	}
	// Custom XML properties
	if doc.CustomProps["Classification"] != "Top Secret" {
		t.Errorf("expected Classification='Top Secret', got %q", doc.CustomProps["Classification"])
	}
	if doc.CustomProps["Reviewer"] != "Alice" {
		t.Errorf("expected Reviewer='Alice', got %q", doc.CustomProps["Reviewer"])
	}
}

func TestExtractOOXMLFromBytesMinimalCore(t *testing.T) {
	// Just core.xml with title and creator
	coreMinimal := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:creator>Minimal Author</dc:creator>
  <dc:title>Minimal Title</dc:title>
</coreProperties>`
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": docxCT,
		"word/document.xml":   "<w:document/>",
		"docProps/core.xml":   coreMinimal,
	})
	doc, err := ExtractOOXMLFromBytes(data)
	if err != nil {
		t.Fatalf("ExtractOOXMLFromBytes: %v", err)
	}
	if doc.Author != "Minimal Author" {
		t.Errorf("expected Author='Minimal Author', got %q", doc.Author)
	}
	if doc.Title != "Minimal Title" {
		t.Errorf("expected Title='Minimal Title', got %q", doc.Title)
	}
	if !doc.Created.IsZero() {
		t.Error("expected Created to be zero for missing date")
	}
}

func TestExtractOOXMLFromBytesNoCore(t *testing.T) {
	// Zip with no docProps at all
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": docxCT,
		"word/document.xml":   "<w:document/>",
	})
	doc, err := ExtractOOXMLFromBytes(data)
	if err != nil {
		t.Fatalf("ExtractOOXMLFromBytes: %v", err)
	}
	if doc.Type != "docx" {
		t.Errorf("expected type=docx, got %q", doc.Type)
	}
	if doc.Author != "" {
		t.Errorf("expected empty Author, got %q", doc.Author)
	}
	if doc.CustomProps == nil {
		t.Error("expected CustomProps map to be initialized (not nil)")
	}
}

func TestExtractOOXMLFromBytesMalformedCore(t *testing.T) {
	// core.xml is not valid XML - parser should swallow the error
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": docxCT,
		"word/document.xml":   "<w:document/>",
		"docProps/core.xml":   "<<<not xml>>>",
	})
	doc, err := ExtractOOXMLFromBytes(data)
	if err != nil {
		t.Fatalf("ExtractOOXMLFromBytes: %v", err)
	}
	if doc.Type != "docx" {
		t.Errorf("expected type=docx, got %q", doc.Type)
	}
	if doc.Author != "" {
		t.Errorf("expected empty Author for malformed core, got %q", doc.Author)
	}
}

func TestAnalyzeOOXMLBytes(t *testing.T) {
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": docxCT,
		"word/document.xml":   "<w:document/>",
		"docProps/core.xml":   coreFull,
		"docProps/app.xml":    appFull,
	})
	r := Analyze(data, "report.docx")
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Format != "ooxml" {
		t.Errorf("expected Format=ooxml, got %q", r.Format)
	}
	if r.Type != "docx" {
		t.Errorf("expected Type=docx, got %q", r.Type)
	}
	if r.App != "Microsoft Word" {
		t.Errorf("expected App='Microsoft Word', got %q", r.App)
	}
	if r.Metadata == nil {
		t.Fatal("expected Metadata to be set")
	}
	if r.Metadata.Author != "Jane Doe" {
		t.Errorf("expected Author='Jane Doe', got %q", r.Metadata.Author)
	}
	// OOXML short-circuits macro detection
	if r.HasMacros {
		t.Error("expected HasMacros=false for OOXML input")
	}
}

func TestAnalyzeOOXMLBytesXLSX(t *testing.T) {
	coreMinimal := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:creator>Spreadsheet User</dc:creator>
</coreProperties>`
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": xlsxCT,
		"xl/workbook.xml":     "<workbook/>",
		"docProps/core.xml":   coreMinimal,
	})
	r := Analyze(data, "sheet.xlsx")
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Type != "xlsx" {
		t.Errorf("expected Type=xlsx, got %q", r.Type)
	}
	if r.App != "Microsoft Excel" {
		t.Errorf("expected App='Microsoft Excel', got %q", r.App)
	}
}

func TestAnalyzeOOXMLBytesPPTX(t *testing.T) {
	coreMinimal := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:creator>Slide User</dc:creator>
</coreProperties>`
	data := buildZip(t, map[string]string{
		"[Content_Types].xml": pptxCT,
		"ppt/presentation.xml": "<presentation/>",
		"docProps/core.xml":   coreMinimal,
	})
	r := Analyze(data, "deck.pptx")
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Type != "pptx" {
		t.Errorf("expected Type=pptx, got %q", r.Type)
	}
	if r.App != "Microsoft PowerPoint" {
		t.Errorf("expected App='Microsoft PowerPoint', got %q", r.App)
	}
}

func TestAnalyzeOOXMLBytesShortInput(t *testing.T) {
	// Less than 512 bytes - should return early without panic
	r := Analyze([]byte{0x50, 0x4B, 0x03, 0x04}, "tiny.docx")
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Format != "" {
		t.Errorf("expected empty Format for too-short input, got %q", r.Format)
	}
}

func TestOOXMLAppNameUnknown(t *testing.T) {
	got := ooxmlAppName("unknown")
	if got != "Microsoft Office" {
		t.Errorf("expected fallback 'Microsoft Office', got %q", got)
	}
}

func TestAnalyzeOLE2Format(t *testing.T) {
	// Construct minimal OLE2 (D0 CF 11 E0 ...) to verify Format=ole2 is set.
	ole2 := append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, make([]byte, 600)...)
	r := Analyze(ole2, "legacy.doc")
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Format != "ole2" {
		t.Errorf("expected Format=ole2, got %q", r.Format)
	}
}

func TestFormatOOXMLBytesMinimal(t *testing.T) {
	doc := &OOXMLDocument{
		Type:        "docx",
		Author:      "Test",
		Title:       "Doc",
		CustomProps: map[string]interface{}{},
	}
	out := FormatOOXML(doc)
	if out == "" {
		t.Error("expected non-empty output")
	}
	if !bytes.Contains([]byte(out), []byte("Author: Test")) {
		t.Errorf("expected 'Author: Test' in output, got: %s", out)
	}
}
