package evtx

import (
	"testing"
	"time"
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
		{99, "Unknown"},
	}

	for _, tt := range tests {
		if got := levelName(tt.level); got != tt.want {
			t.Errorf("levelName(%d) = %v, want %v", tt.level, got, tt.want)
		}
	}
}

func TestAnalyze_ValidHeader(t *testing.T) {
	// Create a minimal valid EVTX header
	data := make([]byte, 4096)
	copy(data[:8], "ElfFile\x00")

	_, err := Analyze(data, "test.evtx")
	// Should not error on valid header, but no chunks
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestEventCreation(t *testing.T) {
	event := Event{
		TimeCreated: time.Now(),
		EventID:     4624,
		Level:       4,
		Provider:    "Microsoft-Windows-Security-Auditing",
		Computer:    "WORKSTATION1",
		Message:     "Logon successful",
		Channel:     "Security",
		LevelName:   "Information",
	}

	if event.EventID != 4624 {
		t.Errorf("Expected EventID 4624, got %d", event.EventID)
	}

	if event.LevelName != "Information" {
		t.Errorf("Expected LevelName Information, got %s", event.LevelName)
	}
}

func TestParseChunk(t *testing.T) {
	// Test with empty chunk
	events := parseChunk([]byte{})
	if len(events) != 0 {
		t.Errorf("Expected 0 events from empty chunk, got %d", len(events))
	}
}

func TestSuspiciousEventIDs(t *testing.T) {
	// Test that suspicious events are detected
	suspiciousIDs := []uint16{4625, 4648, 4697, 4698, 4720, 4722}
	for _, id := range suspiciousIDs {
		if _, ok := suspiciousEventIDs[id]; !ok {
			t.Errorf("Event ID %d should be in suspiciousEventIDs", id)
		}
	}
}

func TestResultStats(t *testing.T) {
	result := &Result{
		FileName:   "test.evtx",
		TotalEvents: 10,
		Events: []Event{
			{Provider: "Test", LevelName: "Information"},
			{Provider: "Test", LevelName: "Error"},
		},
		Stats: make(map[string]int),
	}

	// Calculate stats
	for _, event := range result.Events {
		result.Stats[event.Provider]++
		result.Stats[event.LevelName]++
	}

	if result.Stats["Test"] != 2 {
		t.Errorf("Expected 2 Test events, got %d", result.Stats["Test"])
	}

	if result.Stats["Information"] != 1 {
		t.Errorf("Expected 1 Information event, got %d", result.Stats["Information"])
	}

	if result.Stats["Error"] != 1 {
		t.Errorf("Expected 1 Error event, got %d", result.Stats["Error"])
	}
}

func TestPrint(t *testing.T) {
	result := &Result{
		FileName:   "test.evtx",
		TotalEvents: 5,
		Events: []Event{
			{EventID: 4624, LevelName: "Information"},
		},
		Stats: map[string]int{
			"Information": 1,
		},
		Flags: []string{"Event 4624: Successful logon"},
	}

	// Test that Print doesn't panic
	Print(result)
}
