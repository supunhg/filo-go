package registry

import (
	"testing"
)

func TestDetectHiveType(t *testing.T) {
	tests := []struct {
		fileName string
		hiveName string
		want     string
	}{
		{"SAM", "", "SAM"},
		{"SYSTEM", "", "SYSTEM"},
		{"SOFTWARE", "", "SOFTWARE"},
		{"SECURITY", "", "SECURITY"},
		{"NTUSER.DAT", "", "USER"},
		{"UsrClass.dat", "", "UNKNOWN"},
		{"unknown", "", "UNKNOWN"},
	}

	for _, tt := range tests {
		got := DetectHiveType(tt.fileName, tt.hiveName)
		if got != tt.want {
			t.Errorf("DetectHiveType(%s, %s) = %s, want %s", tt.fileName, tt.hiveName, got, tt.want)
		}
	}
}

func TestAnalyze(t *testing.T) {
	// Test with empty data
	_, err := Analyze([]byte{}, "test.reg")
	if err == nil {
		t.Error("Expected error for empty data")
	}

	// Test with invalid data
	_, err = Analyze([]byte("invalid"), "test.reg")
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}
