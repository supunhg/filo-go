package export

import (
	"os"
	"testing"
)

func TestGenerateHTMLReport(t *testing.T) {
	// Create test results
	results := &AnalysisResults{
		Timestamp: "2024-01-01 00:00:00",
		FileInfo: &FileInfo{
			Name:    "test.txt",
			Size:    1024,
			Type:    "text/plain",
			MIME:    "text/plain",
			SHA256:  "abc123",
			Entropy: 4.5,
		},
		Signatures: []SignatureMatch{
			{Name: "Text", Description: "Plain text file", Offset: 0, Confidence: 0.9},
		},
		Strings: []ExtractedString{
			{Offset: 0, Type: "ASCII", Value: "Hello, World!"},
		},
		Metadata: map[string]interface{}{
			"Line endings": "Unix",
		},
		SecurityIssues: []SecurityIssue{
			{Severity: "low", Type: "info", Description: "No security issues found"},
		},
	}

	// Generate report
	tmpFile, err := os.CreateTemp("", "test-report-*.html")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	err = GenerateHTMLReport(results, tmpFile.Name())
	if err != nil {
		t.Fatalf("GenerateHTMLReport() error = %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		t.Error("Report file was not created")
	}

	// Read and verify content
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read report: %v", err)
	}

	html := string(content)
	if !contains(html, "Filo Analysis Report") {
		t.Error("Report missing title")
	}
	if !contains(html, "test.txt") {
		t.Error("Report missing file name")
	}
	if !contains(html, "abc123") {
		t.Error("Report missing SHA256")
	}
}

func TestFormatHTMLPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/path/to/file.txt", "/path/to/file.html"},
		{"/path/to/file.tar.gz", "/path/to/file.tar.html"},
		{"file.txt", "file.html"},
	}

	for _, tt := range tests {
		got := FormatHTMLPath(tt.input)
		if got != tt.want {
			t.Errorf("FormatHTMLPath(%s) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
