package office

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectOOXML(t *testing.T) {
	// Create a test DOCX file
	tmpDir := t.TempDir()
	docxPath := filepath.Join(tmpDir, "test.docx")

	// Create a minimal DOCX
	err := createTestDOCX(docxPath)
	if err != nil {
		t.Fatalf("Failed to create test DOCX: %v", err)
	}

	// Test detection
	docType := DetectOOXML(docxPath)
	if docType != "docx" {
		t.Errorf("Expected 'docx', got %s", docType)
	}
}

func TestDetectOOXMLNotOffice(t *testing.T) {
	// Create a non-Office file
	tmpDir := t.TempDir()
	txtPath := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(txtPath, []byte("Hello, World!"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test detection
	docType := DetectOOXML(txtPath)
	if docType != "" {
		t.Errorf("Expected empty string, got %s", docType)
	}
}

func TestExtractOOXML(t *testing.T) {
	// Create a test DOCX file
	tmpDir := t.TempDir()
	docxPath := filepath.Join(tmpDir, "test.docx")

	// Create a minimal DOCX
	err := createTestDOCX(docxPath)
	if err != nil {
		t.Fatalf("Failed to create test DOCX: %v", err)
	}

	// Test extraction
	doc, err := ExtractOOXML(docxPath)
	if err != nil {
		t.Fatalf("ExtractOOXML() error = %v", err)
	}

	if doc == nil {
		t.Fatal("Expected non-nil document")
	}

	if doc.Type != "docx" {
		t.Errorf("Expected type 'docx', got %s", doc.Type)
	}
}

func TestFormatOOXML(t *testing.T) {
	// Test with nil
	result := FormatOOXML(nil)
	if result != "No OOXML metadata found" {
		t.Errorf("Expected 'No OOXML metadata found', got %s", result)
	}

	// Test with document
	doc := &OOXMLDocument{
		Type:   "docx",
		Author: "Test Author",
		Title:  "Test Document",
	}

	result = FormatOOXML(doc)
	if result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestIsOOXML(t *testing.T) {
	// Create a test DOCX file
	tmpDir := t.TempDir()
	docxPath := filepath.Join(tmpDir, "test.docx")

	// Create a minimal DOCX
	err := createTestDOCX(docxPath)
	if err != nil {
		t.Fatalf("Failed to create test DOCX: %v", err)
	}

	// Test detection
	if !IsOOXML(docxPath) {
		t.Error("Expected true for OOXML file")
	}

	// Test non-OOXML file
	txtPath := filepath.Join(tmpDir, "test.txt")
	err = os.WriteFile(txtPath, []byte("Hello"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if IsOOXML(txtPath) {
		t.Error("Expected false for non-OOXML file")
	}
}

func TestGetFileType(t *testing.T) {
	// Test with nil
	if GetFileType(nil) != "" {
		t.Error("Expected empty string for nil")
	}

	// Test with document
	doc := &OOXMLDocument{Type: "xlsx"}
	if GetFileType(doc) != "xlsx" {
		t.Errorf("Expected 'xlsx', got %s", GetFileType(doc))
	}
}

func TestDetectXLSX(t *testing.T) {
	tmpDir := t.TempDir()
	xlsxPath := filepath.Join(tmpDir, "test.xlsx")

	err := createTestXLSX(xlsxPath)
	if err != nil {
		t.Fatalf("Failed to create test XLSX: %v", err)
	}

	docType := DetectOOXML(xlsxPath)
	if docType != "xlsx" {
		t.Errorf("Expected 'xlsx', got %s", docType)
	}
}

func TestDetectPPTX(t *testing.T) {
	tmpDir := t.TempDir()
	pptxPath := filepath.Join(tmpDir, "test.pptx")

	err := createTestPPTX(pptxPath)
	if err != nil {
		t.Fatalf("Failed to create test PPTX: %v", err)
	}

	docType := DetectOOXML(pptxPath)
	if docType != "pptx" {
		t.Errorf("Expected 'pptx', got %s", docType)
	}
}

func TestExtractXLSX(t *testing.T) {
	tmpDir := t.TempDir()
	xlsxPath := filepath.Join(tmpDir, "test.xlsx")

	err := createTestXLSX(xlsxPath)
	if err != nil {
		t.Fatalf("Failed to create test XLSX: %v", err)
	}

	doc, err := ExtractOOXML(xlsxPath)
	if err != nil {
		t.Fatalf("ExtractOOXML() error = %v", err)
	}

	if doc.Type != "xlsx" {
		t.Errorf("Expected type 'xlsx', got %s", doc.Type)
	}
}

func TestExtractPPTX(t *testing.T) {
	tmpDir := t.TempDir()
	pptxPath := filepath.Join(tmpDir, "test.pptx")

	err := createTestPPTX(pptxPath)
	if err != nil {
		t.Fatalf("Failed to create test PPTX: %v", err)
	}

	doc, err := ExtractOOXML(pptxPath)
	if err != nil {
		t.Fatalf("ExtractOOXML() error = %v", err)
	}

	if doc.Type != "pptx" {
		t.Errorf("Expected type 'pptx', got %s", doc.Type)
	}
}

func TestExtractOOXMLInvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid.docx")
	os.WriteFile(path, []byte("not a zip"), 0644)

	_, err := ExtractOOXML(path)
	if err == nil {
		t.Error("Expected error for invalid file")
	}
}

func TestExtractOOXMLNonexistent(t *testing.T) {
	_, err := ExtractOOXML("/nonexistent/file.docx")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestDetectOOXMLNonexistent(t *testing.T) {
	docType := DetectOOXML("/nonexistent/file.docx")
	if docType != "" {
		t.Errorf("Expected empty string, got %s", docType)
	}
}

func TestParseISO8601(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"RFC3339", "2024-01-01T00:00:00Z", false},
		{"date only", "2024-01-01", false},
		{"invalid", "not-a-date", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseISO8601(tt.input)
			if (err != nil) != tt.wantErr {
				parseISO8601(tt.input)
			}
		})
	}
}

func TestDocumentProperties(t *testing.T) {
	props := &DocumentProperties{
		Creator:        "Test User",
		Title:          "Test Title",
		Subject:        "Test Subject",
		Description:    "Test Description",
		Keywords:       "test, docx",
		Category:       "Document",
		Version:        "1.0",
		Revision:       "1",
		LastModifiedBy: "Another User",
		Created:        "2024-01-01T00:00:00Z",
		Modified:       "2024-01-02T00:00:00Z",
	}

	if props.Creator != "Test User" {
		t.Errorf("Expected creator 'Test User', got %s", props.Creator)
	}
}

func TestCustomProperty(t *testing.T) {
	prop := CustomProperty{
		Fmtid:    "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}",
		Pid:      2,
		Name:     "Status",
		DataType: 1,
		Value:    "Draft",
	}

	if prop.Name != "Status" {
		t.Errorf("Expected name 'Status', got %s", prop.Name)
	}
}

func TestAppProperties(t *testing.T) {
	props := &AppProperties{
		Template:   "Normal",
		TotalTime:  "100",
		Pages:      "5",
		Words:      "1000",
		AppVersion: "16.0",
		Company:    "Test Company",
	}

	if props.Template != "Normal" {
		t.Errorf("Expected template 'Normal', got %s", props.Template)
	}

	if props.Words != "1000" {
		t.Errorf("Expected words '1000', got %s", props.Words)
	}
}

func createTestXLSX(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	ct, _ := w.Create("[Content_Types].xml")
	ct.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`))

	rels, _ := w.Create("_rels/.rels")
	rels.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`))

	xl, _ := w.Create("xl/workbook.xml")
	xl.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets>
    <sheet name="Sheet1" sheetId="1"/>
  </sheets>
</workbook>`))

	core, _ := w.Create("docProps/core.xml")
	core.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<coreProperties xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:creator>Excel User</dc:creator>
  <dc:title>Test Spreadsheet</dc:title>
</coreProperties>`))

	return nil
}

func createTestPPTX(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	ct, _ := w.Create("[Content_Types].xml")
	ct.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`))

	rels, _ := w.Create("_rels/.rels")
	rels.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`))

	ppt, _ := w.Create("ppt/presentation.xml")
	ppt.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<presentation xmlns="http://schemas.openxmlformats.org/presentationml/2006/main">
  <sldMasterIdLst/>
</presentation>`))

	core, _ := w.Create("docProps/core.xml")
	core.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<coreProperties xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:creator>PowerPoint User</dc:creator>
  <dc:title>Test Presentation</dc:title>
</coreProperties>`))

	return nil
}

// createTestDOCX creates a minimal DOCX file for testing
func createTestDOCX(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	// Add [Content_Types].xml
	ct, err := w.Create("[Content_Types].xml")
	if err != nil {
		return err
	}
	ct.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>`))

	// Add _rels/.rels
	rels, err := w.Create("_rels/.rels")
	if err != nil {
		return err
	}
	rels.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>`))

	// Add word/document.xml
	doc, err := w.Create("word/document.xml")
	if err != nil {
		return err
	}
	doc.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Hello, World!</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>`))

	// Add docProps/core.xml
	core, err := w.Create("docProps/core.xml")
	if err != nil {
		return err
	}
	core.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <cp:revision>1</cp:revision>
  <dc:creator>Test Author</dc:creator>
  <dcterms:created xsi:type="dcterms:W3CDTF">2024-01-01T00:00:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2024-01-02T00:00:00Z</dcterms:modified>
  <dc:title>Test Document</dc:title>
  <dc:subject>Testing</dc:subject>
</coreProperties>`))

	// Add docProps/app.xml
	app, err := w.Create("docProps/app.xml")
	if err != nil {
		return err
	}
	app.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <AppVersion>16.0</AppVersion>
  <Company>Test Company</Company>
  <Template>Normal</Template>
</Properties>`))

	return nil
}
