package entropy

import "testing"

func TestCalculate(t *testing.T) {
	// All same bytes = 0 entropy
	uniform := make([]byte, 1000)
	for i := range uniform {
		uniform[i] = 0x41
	}
	if e := Calculate(uniform); e != 0.0 {
		t.Errorf("uniform data should have 0 entropy, got %f", e)
	}

	// Random-ish data = high entropy
	random := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if e := Calculate(random); e < 2.0 {
		t.Errorf("random data should have high entropy, got %f", e)
	}

	// Empty data
	if e := Calculate(nil); e != 0.0 {
		t.Errorf("nil data should have 0 entropy, got %f", e)
	}
}

func TestInterpret(t *testing.T) {
	tests := []struct {
		entropy  float64
		expected string
	}{
		{0.5, "Very low"},
		{2.0, "Low"},
		{4.0, "Medium"},
		{6.0, "High"},
		{7.5, "Very high"},
	}

	for _, tt := range tests {
		result := Interpret(tt.entropy)
		if len(result) < len(tt.expected) || result[:len(tt.expected)] != tt.expected {
			t.Errorf("Interpret(%f) = %q, want prefix %q", tt.entropy, result, tt.expected)
		}
	}
}

func TestChunks(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i % 16)
	}

	chunks := Chunks(data, 25)
	if len(chunks) != 4 {
		t.Errorf("expected 4 chunks, got %d", len(chunks))
	}

	// Each chunk should have some entropy
	for i, c := range chunks {
		if c.Entropy < 0 {
			t.Errorf("chunk %d has negative entropy: %f", i, c.Entropy)
		}
	}
}

func TestBar(t *testing.T) {
	bar := Bar(4.0, 20)
	if len(bar) == 0 {
		t.Error("Bar returned empty string")
	}
}
