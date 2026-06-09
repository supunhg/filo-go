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
