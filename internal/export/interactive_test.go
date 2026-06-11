package export

import (
	"os"
	"testing"
)

func TestGenerateInteractiveReport(t *testing.T) {
	results := &AnalysisResults{
		Timestamp: "2026-06-11T00:00:00Z",
		FileInfo: &FileInfo{
			Name:    "test.bin",
			Size:    1024,
			Type:    "binary",
			MIME:    "application/octet-stream",
			SHA256:  "abc123def456",
			Entropy: 5.5,
		},
		Signatures: []SignatureMatch{
			{Name: "PNG", Description: "PNG image", Offset: 0, Confidence: 0.95},
			{Name: "ZIP", Description: "ZIP archive", Offset: 500, Confidence: 0.85},
		},
		Strings: []ExtractedString{
			{Offset: 0, Type: "ascii", Value: "Hello World"},
			{Offset: 12, Type: "ascii", Value: "Test String"},
		},
		Metadata: map[string]interface{}{
			"author": "test",
			"date":   "2024-01-01",
		},
		SecurityIssues: []SecurityIssue{
			{Severity: "high", Type: "encryption", Description: "High entropy detected"},
			{Severity: "medium", Type: "obfuscation", Description: "Possible obfuscation"},
		},
	}

	tmpFile := t.TempDir() + "/interactive.html"
	err := GenerateInteractiveReport(results, tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("output file is empty")
	}

	html := string(data)
	if len(html) < 100 {
		t.Error("HTML output too short")
	}
}

func TestGenerateInteractiveReportMinimal(t *testing.T) {
	results := &AnalysisResults{
		Timestamp: "2026-06-11T00:00:00Z",
	}

	tmpFile := t.TempDir() + "/minimal.html"
	err := GenerateInteractiveReport(results, tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("output file is empty")
	}
}

func TestBuildSummary(t *testing.T) {
	results := &AnalysisResults{
		FileInfo: &FileInfo{Entropy: 7.5},
		SecurityIssues: []SecurityIssue{
			{Severity: "high", Type: "test", Description: "test"},
		},
	}

	summary := buildSummary(results)
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}

	if summary.Entropy != 7.5 {
		t.Errorf("expected entropy 7.5, got %f", summary.Entropy)
	}

	if summary.TotalIssues != 1 {
		t.Errorf("expected 1 issue, got %d", summary.TotalIssues)
	}

	if summary.RiskLevel == "" {
		t.Error("expected risk level to be set")
	}
}

func TestBuildInteractiveReport(t *testing.T) {
	results := &AnalysisResults{
		Timestamp: "2026-06-11T00:00:00Z",
		FileInfo: &FileInfo{
			Name:    "test.bin",
			Size:    1024,
			Type:    "binary",
			SHA256:  "abc123",
			Entropy: 5.0,
		},
		Signatures: []SignatureMatch{
			{Name: "test", Description: "test sig", Offset: 0, Confidence: 0.9},
		},
	}

	report := buildInteractiveReport(results)
	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if report.Title == "" {
		t.Error("expected title to be set")
	}

	if len(report.Sections) == 0 {
		t.Error("expected sections to be populated")
	}
}

func TestBuildSummaryRiskLevels(t *testing.T) {
	tests := []struct {
		name     string
		issues   int
		entropy  float64
		expected string
	}{
		{"info", 0, 3.0, "info"},
		{"low", 0, 7.5, "low"},
		{"medium", 2, 5.0, "medium"},
		{"high", 3, 7.5, "critical"},
		{"critical", 5, 8.0, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &AnalysisResults{
				FileInfo: &FileInfo{Entropy: tt.entropy},
			}
			for i := 0; i < tt.issues; i++ {
				results.SecurityIssues = append(results.SecurityIssues, SecurityIssue{
					Severity: "high", Type: "test", Description: "test",
				})
			}

			summary := buildSummary(results)
			if summary.RiskLevel != tt.expected {
				t.Errorf("expected risk level %s, got %s (score: %f)", tt.expected, summary.RiskLevel, summary.RiskScore)
			}
		})
	}
}
