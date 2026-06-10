package office

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// OOXMLDocument represents an Office Open XML document
type OOXMLDocument struct {
	Type        string // docx, xlsx, pptx
	Properties  *DocumentProperties
	CustomProps map[string]interface{}
	Author      string
	Title       string
	Subject     string
	Keywords    string
	Comments    string
	Category    string
	Created     time.Time
	Modified    time.Time
	LastSavedBy string
	Revision    string
	Version     string
}

// DocumentProperties represents core document properties
type DocumentProperties struct {
	XMLName        xml.Name `xml:"http://schemas.openxmlformats.org/package/2006/metadata/core-properties coreProperties"`
	Creator        string   `xml:"creator"`
	Title          string   `xml:"title"`
	Subject        string   `xml:"subject"`
	Description    string   `xml:"description"`
	Keywords       string   `xml:"keywords"`
	Category       string   `xml:"category"`
	Version        string   `xml:"version"`
	Revision       string   `xml:"revision"`
	LastModifiedBy string   `xml:"lastModifiedBy"`
	Created        string   `xml:"created"`
	Modified       string   `xml:"modified"`
	ContentStatus  string   `xml:"contentStatus"`
	Language       string   `xml:"language"`
	Identifier     string   `xml:"identifier"`
}

// CustomProperties represents custom document properties
type CustomProperties struct {
	XMLName  xml.Name         `xml:"http://schemas.openxmlformats.org/officeDocument/2006/custom-properties Properties"`
	Property []CustomProperty `xml:"property"`
}

// VTProperty holds the typed value of a custom property.
// The vt: prefix in OOXML custom.xml can be one of lpwstr (string), i4 (int),
// bool, filetime, r8 (double), or blob (base64 binary).
type VTProperty struct {
	LPWStr   string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes lpwstr"`
	LPSTR    string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes lpstr"`
	Blob     string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes blob"`
	I4       string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes i4"`
	I8       string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes i8"`
	R4       string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes r4"`
	R8       string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes r8"`
	Bool     string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes bool"`
	Filetime string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes filetime"`
}

// CustomProperty represents a single custom property. The OOXML spec allows
// the value to be one of several vt: types (lpwstr, lpstr, i4, i8, r4, r8,
// bool, filetime, blob). All variants are decoded into their respective
// fields; VTValue() returns the first non-empty one in priority order.
type CustomProperty struct {
	Fmtid    string `xml:"fmtid,attr"`
	Pid      int    `xml:"pid,attr"`
	Name     string `xml:"name,attr"`
	LPWStr   string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes lpwstr"`
	LPSTR    string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes lpstr"`
	I4       string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes i4"`
	I8       string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes i8"`
	R4       string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes r4"`
	R8       string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes r8"`
	Bool     string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes bool"`
	Filetime string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes filetime"`
	Blob     string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes blob"`
}

// VTValue returns the best-effort string representation of the typed value.
func (p CustomProperty) VTValue() string {
	switch {
	case p.LPWStr != "":
		return p.LPWStr
	case p.LPSTR != "":
		return p.LPSTR
	case p.Blob != "":
		return p.Blob
	case p.I4 != "":
		return p.I4
	case p.I8 != "":
		return p.I8
	case p.R4 != "":
		return p.R4
	case p.R8 != "":
		return p.R8
	case p.Bool != "":
		return p.Bool
	case p.Filetime != "":
		return p.Filetime
	}
	return ""
}

// AppProperties represents application-specific properties
type AppProperties struct {
	XMLName              xml.Name `xml:"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties Properties"`
	Template             string   `xml:"Template"`
	TotalTime            string   `xml:"TotalTime"`
	Pages                string   `xml:"Pages"`
	Words                string   `xml:"Words"`
	Characters           string   `xml:"Characters"`
	CharactersWithSpaces string   `xml:"CharactersWithSpaces"`
	Lines                string   `xml:"Lines"`
	Paragraphs           string   `xml:"Paragraphs"`
	ScaleCrop            string   `xml:"ScaleCrop"`
	LinksUpToDate        string   `xml:"LinksUpToDate"`
	SharedDoc            string   `xml:"SharedDoc"`
	HyperlinksChanged    string   `xml:"HyperlinksChanged"`
	AppVersion           string   `xml:"AppVersion"`
	Company              string   `xml:"Company"`
	DocSecurity          string   `xml:"DocSecurity"`
}

// DetectOOXMLBytes detects if an in-memory buffer is an OOXML document.
// Returns "docx", "xlsx", "pptx" or "".
func DetectOOXMLBytes(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	// ZIP local file header magic: "PK\x03\x04"
	if data[0] != 0x50 || data[1] != 0x4B || data[2] != 0x03 || data[3] != 0x04 {
		return ""
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return ""
	}

	hasContentTypes := false
	hasWord := false
	hasXL := false
	hasPowerPoint := false
	for _, f := range zr.File {
		name := f.Name
		if name == "[Content_Types].xml" {
			hasContentTypes = true
		}
		if strings.HasPrefix(name, "word/") {
			hasWord = true
		}
		if strings.HasPrefix(name, "xl/") {
			hasXL = true
		}
		if strings.HasPrefix(name, "ppt/") {
			hasPowerPoint = true
		}
	}

	if !hasContentTypes {
		return ""
	}
	if hasWord {
		return "docx"
	}
	if hasXL {
		return "xlsx"
	}
	if hasPowerPoint {
		return "pptx"
	}
	return ""
}

// ExtractOOXMLFromBytes extracts metadata from an in-memory OOXML document.
func ExtractOOXMLFromBytes(data []byte) (*OOXMLDocument, error) {
	docType := DetectOOXMLBytes(data)
	if docType == "" {
		return nil, fmt.Errorf("not an OOXML document")
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to open ZIP: %w", err)
	}

	doc := &OOXMLDocument{
		Type:        docType,
		CustomProps: make(map[string]interface{}),
	}

	for _, f := range zr.File {
		switch f.Name {
		case "docProps/core.xml":
			if d, err := readZipFile(f); err == nil {
				doc.parseCoreProperties(d)
			}
		case "docProps/app.xml":
			if d, err := readZipFile(f); err == nil {
				doc.parseAppProperties(d)
			}
		case "docProps/custom.xml":
			if d, err := readZipFile(f); err == nil {
				doc.parseCustomProperties(d)
			}
		}
	}

	return doc, nil
}

// DetectOOXML detects if a file is an OOXML document
func DetectOOXML(filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Read first 4 bytes (ZIP header)
	header := make([]byte, 4)
	if _, err := io.ReadFull(f, header); err != nil {
		return ""
	}

	// Check for ZIP signature
	if header[0] != 0x50 || header[1] != 0x4B {
		return ""
	}

	// Open as ZIP and check for OOXML content types
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return ""
	}
	defer r.Close()

	// Check for [Content_Types].xml
	hasContentTypes := false
	hasWord := false
	hasXL := false
	hasPowerPoint := false

	for _, f := range r.File {
		name := f.Name
		if name == "[Content_Types].xml" {
			hasContentTypes = true
		}
		if strings.HasPrefix(name, "word/") {
			hasWord = true
		}
		if strings.HasPrefix(name, "xl/") {
			hasXL = true
		}
		if strings.HasPrefix(name, "ppt/") {
			hasPowerPoint = true
		}
	}

	if !hasContentTypes {
		return ""
	}

	if hasWord {
		return "docx"
	}
	if hasXL {
		return "xlsx"
	}
	if hasPowerPoint {
		return "pptx"
	}

	return ""
}

// ExtractOOXML extracts metadata from an OOXML document
func ExtractOOXML(filePath string) (*OOXMLDocument, error) {
	docType := DetectOOXML(filePath)
	if docType == "" {
		return nil, fmt.Errorf("not an OOXML document")
	}

	r, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ZIP: %w", err)
	}
	defer r.Close()

	doc := &OOXMLDocument{
		Type:        docType,
		CustomProps: make(map[string]interface{}),
	}

	// Extract core properties
	for _, f := range r.File {
		if f.Name == "docProps/core.xml" {
			data, err := readZipFile(f)
			if err != nil {
				continue
			}
			doc.parseCoreProperties(data)
		}
		if f.Name == "docProps/app.xml" {
			data, err := readZipFile(f)
			if err != nil {
				continue
			}
			doc.parseAppProperties(data)
		}
		if f.Name == "docProps/custom.xml" {
			data, err := readZipFile(f)
			if err != nil {
				continue
			}
			doc.parseCustomProperties(data)
		}
	}

	return doc, nil
}

// parseCoreProperties parses the core.xml file
func (d *OOXMLDocument) parseCoreProperties(data []byte) {
	props := &DocumentProperties{}
	if err := xml.Unmarshal(data, props); err != nil {
		return
	}

	d.Author = props.Creator
	d.Title = props.Title
	d.Subject = props.Subject
	d.Keywords = props.Keywords
	d.Comments = props.Description
	d.Category = props.Category
	d.Version = props.Version
	d.Revision = props.Revision
	d.LastSavedBy = props.LastModifiedBy

	// Parse dates
	if props.Created != "" {
		if t, err := parseISO8601(props.Created); err == nil {
			d.Created = t
		}
	}
	if props.Modified != "" {
		if t, err := parseISO8601(props.Modified); err == nil {
			d.Modified = t
		}
	}
}

// parseAppProperties parses the app.xml file
func (d *OOXMLDocument) parseAppProperties(data []byte) {
	props := &AppProperties{}
	if err := xml.Unmarshal(data, props); err != nil {
		return
	}

	d.CustomProps["Template"] = props.Template
	d.CustomProps["TotalTime"] = props.TotalTime
	d.CustomProps["Pages"] = props.Pages
	d.CustomProps["Words"] = props.Words
	d.CustomProps["Characters"] = props.Characters
	d.CustomProps["Lines"] = props.Lines
	d.CustomProps["Paragraphs"] = props.Paragraphs
	d.CustomProps["AppVersion"] = props.AppVersion
	d.CustomProps["Company"] = props.Company
	d.CustomProps["DocSecurity"] = props.DocSecurity
}

// parseCustomProperties parses the custom.xml file
func (d *OOXMLDocument) parseCustomProperties(data []byte) {
	props := &CustomProperties{}
	if err := xml.Unmarshal(data, props); err != nil {
		return
	}

	for _, prop := range props.Property {
		d.CustomProps[prop.Name] = prop.VTValue()
	}
}

// readZipFile reads a file from a ZIP archive
func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	return io.ReadAll(rc)
}

// parseISO8601 parses an ISO 8601 date string
func parseISO8601(s string) (time.Time, error) {
	// Try various formats
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", s)
}

// FormatOOXML formats OOXML metadata for display
func FormatOOXML(doc *OOXMLDocument) string {
	if doc == nil {
		return "No OOXML metadata found"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("OOXML Document (%s):\n", strings.ToUpper(doc.Type)))

	if doc.Author != "" {
		sb.WriteString(fmt.Sprintf("  Author: %s\n", doc.Author))
	}
	if doc.Title != "" {
		sb.WriteString(fmt.Sprintf("  Title: %s\n", doc.Title))
	}
	if doc.Subject != "" {
		sb.WriteString(fmt.Sprintf("  Subject: %s\n", doc.Subject))
	}
	if doc.Keywords != "" {
		sb.WriteString(fmt.Sprintf("  Keywords: %s\n", doc.Keywords))
	}
	if doc.Category != "" {
		sb.WriteString(fmt.Sprintf("  Category: %s\n", doc.Category))
	}
	if doc.LastSavedBy != "" {
		sb.WriteString(fmt.Sprintf("  Last Saved By: %s\n", doc.LastSavedBy))
	}
	if doc.Version != "" {
		sb.WriteString(fmt.Sprintf("  Version: %s\n", doc.Version))
	}
	if doc.Revision != "" {
		sb.WriteString(fmt.Sprintf("  Revision: %s\n", doc.Revision))
	}
	if !doc.Created.IsZero() {
		sb.WriteString(fmt.Sprintf("  Created: %s\n", doc.Created.Format(time.RFC3339)))
	}
	if !doc.Modified.IsZero() {
		sb.WriteString(fmt.Sprintf("  Modified: %s\n", doc.Modified.Format(time.RFC3339)))
	}

	// App properties
	if len(doc.CustomProps) > 0 {
		sb.WriteString("\n  Application Properties:\n")
		for key, value := range doc.CustomProps {
			if value != "" && value != "0" {
				sb.WriteString(fmt.Sprintf("    %s: %s\n", key, value))
			}
		}
	}

	return sb.String()
}

// GetFileType returns the specific OOXML file type
func GetFileType(doc *OOXMLDocument) string {
	if doc == nil {
		return ""
	}
	return doc.Type
}

// IsOOXML checks if a file is OOXML
func IsOOXML(filePath string) bool {
	return DetectOOXML(filePath) != ""
}
