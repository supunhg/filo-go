package evtx

import (
	"testing"
)

func TestAnalyze(t *testing.T) {
	// Test with empty data
	_, err := Analyze([]byte{}, "test.evtx")
	if err == nil {
		t.Error("Expected error for empty data")
	}

	// Test with invalid data
	_, err = Analyze([]byte("invalid"), "test.evtx")
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}

func TestLevelName(t *testing.T) {
	tests := []struct {
		level uint8
		want  string
	}{
		{0, "LogAlways"},
		{1, "Critical"},
		{2, "Error"},
		{3, "Warning"},
		{4, "Information"},
		{5, "Verbose"},
		{255, "Unknown"},
	}

	for _, tt := range tests {
		got := levelName(tt.level)
		if got != tt.want {
			t.Errorf("levelName(%d) = %s, want %s", tt.level, got, tt.want)
		}
	}
}
