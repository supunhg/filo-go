package entropy

import (
	"strings"
	"testing"
)

func TestVisualize(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	result := Visualize(data, nil)
	if result == "" {
		t.Error("expected non-empty visualization")
	}

	// Should contain axis labels
	if !strings.Contains(result, "│") {
		t.Error("expected Y-axis in visualization")
	}
}

func TestVisualizeEmpty(t *testing.T) {
	result := Visualize([]byte{}, nil)
	if !strings.Contains(result, "No data") {
		t.Error("expected 'No data' message for empty input")
	}
}

func TestVisualizeNoColor(t *testing.T) {
	data := make([]byte, 256)
	opts := &VizOptions{
		Width:  20,
		Height: 10,
		Color:  false,
	}

	result := Visualize(data, opts)
	// Should not contain ANSI escape codes
	if strings.Contains(result, "\033[") {
		t.Error("expected no ANSI color codes when color is disabled")
	}
}

func TestMiniViz(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	result := MiniViz(data, 20)
	if result == "" {
		t.Error("expected non-empty mini visualization")
	}

	// Should be roughly the requested width (minus ANSI codes)
	if len(result) < 10 {
		t.Error("visualization seems too short")
	}
}

func TestMiniVizDefaultWidth(t *testing.T) {
	data := make([]byte, 1024)
	result := MiniViz(data, 0)
	if result == "" {
		t.Error("expected non-empty result with default width")
	}
}

func TestProfile(t *testing.T) {
	// Low entropy data (all zeros)
	lowEnt := make([]byte, 1024)

	// High entropy data (random)
	highEnt := make([]byte, 1024)
	for i := range highEnt {
		highEnt[i] = byte(i * 37 % 256)
	}

	// Test low entropy
	profile := Profile(lowEnt, 256)
	if profile.Average >= 1.0 {
		t.Errorf("expected low average entropy, got %f", profile.Average)
	}

	// Test high entropy
	profile = Profile(highEnt, 256)
	if profile.Average < 5.0 {
		t.Errorf("expected high average entropy, got %f", profile.Average)
	}
}

func TestProfileDefaultChunkSize(t *testing.T) {
	data := make([]byte, 1024)
	profile := Profile(data, 0)

	if len(profile.Chunks) == 0 {
		t.Error("expected at least one chunk")
	}
}

func TestProfileMinMax(t *testing.T) {
	// Create data with varying entropy
	data := make([]byte, 2048)
	// First half: low entropy
	for i := 0; i < 1024; i++ {
		data[i] = 0
	}
	// Second half: high entropy
	for i := 1024; i < 2048; i++ {
		data[i] = byte(i * 37 % 256)
	}

	profile := Profile(data, 512)

	if profile.Min >= profile.Max {
		t.Errorf("expected min < max, got min=%f, max=%f", profile.Min, profile.Max)
	}
}

func TestInterpretEntropy(t *testing.T) {
	tests := []struct {
		entropy float64
		contains string
	}{
		{0.5, "Very low"},
		{1.5, "Low"},
		{3.0, "Medium-low"},
		{4.5, "Medium"},
		{6.0, "High"},
		{7.0, "Very high"},
		{7.9, "Maximum"},
	}

	for _, tt := range tests {
		result := InterpretEntropy(tt.entropy)
		if !strings.Contains(result, tt.contains) {
			t.Errorf("InterpretEntropy(%f) = %q, expected to contain %q", tt.entropy, result, tt.contains)
		}
	}
}

func TestEntropyBarChar(t *testing.T) {
	tests := []struct {
		entropy float64
		color   bool
		letter  string
	}{
		{1.0, false, "░"},
		{3.0, false, "▒"},
		{5.0, false, "▓"},
		{7.0, false, "█"},
		{1.0, true, "\033[32m█\033[0m"},
		{3.0, true, "\033[33m█\033[0m"},
		{5.0, true, "\033[31m█\033[0m"},
		{7.0, true, "\033[35m█\033[0m"},
	}

	for _, tt := range tests {
		result := entropyBarChar(tt.entropy, tt.color)
		if result != tt.letter {
			t.Errorf("entropyBarChar(%f, %v) = %q, want %q", tt.entropy, tt.color, result, tt.letter)
		}
	}
}

func TestChunkInfoJSON(t *testing.T) {
	chunk := ChunkInfo{
		Offset:  1024,
		Size:    512,
		Entropy: 6.5,
	}

	if chunk.Offset != 1024 {
		t.Errorf("expected offset 1024, got %d", chunk.Offset)
	}
	if chunk.Size != 512 {
		t.Errorf("expected size 512, got %d", chunk.Size)
	}
	if chunk.Entropy != 6.5 {
		t.Errorf("expected entropy 6.5, got %f", chunk.Entropy)
	}
}

func TestEntropyProfileJSON(t *testing.T) {
	profile := &EntropyProfile{
		Min:     0.0,
		Max:     8.0,
		Average: 4.0,
		Chunks:  []ChunkInfo{},
	}

	if profile.Min != 0.0 {
		t.Errorf("expected min 0.0, got %f", profile.Min)
	}
	if profile.Max != 8.0 {
		t.Errorf("expected max 8.0, got %f", profile.Max)
	}
	if profile.Average != 4.0 {
		t.Errorf("expected average 4.0, got %f", profile.Average)
	}
}

func TestVisualizeCustomSize(t *testing.T) {
	data := make([]byte, 2048)
	opts := &VizOptions{
		Width:  40,
		Height: 15,
		Color:  false,
	}

	result := Visualize(data, opts)
	if result == "" {
		t.Error("expected non-empty visualization")
	}

	// Count lines (should be roughly Height + axis labels)
	lines := strings.Split(result, "\n")
	if len(lines) < opts.Height {
		t.Errorf("expected at least %d lines, got %d", opts.Height, len(lines))
	}
}
