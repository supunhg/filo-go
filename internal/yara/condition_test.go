package yara

import (
	"testing"
)

func TestParseCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		wantErr   bool
	}{
		{"simple string", "$a", false},
		{"and condition", "$a and $b", false},
		{"or condition", "$a or $b", false},
		{"not condition", "not $a", false},
		{"nested condition", "($a and $b) or $c", false},
		{"filesize condition", "filesize < 1024", false},
		{"complex condition", "($a or $b) and filesize > 512", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCondition(tt.condition)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCondition() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAndCondition(t *testing.T) {
	cond := &AndCondition{
		Left:  &StringCondition{StringID: "$a"},
		Right: &StringCondition{StringID: "$b"},
	}

	// Test String()
	s := cond.String()
	if s != "($a AND $b)" {
		t.Errorf("Expected '($a AND $b)', got %s", s)
	}
}

func TestOrCondition(t *testing.T) {
	cond := &OrCondition{
		Left:  &StringCondition{StringID: "$a"},
		Right: &StringCondition{StringID: "$b"},
	}

	// Test String()
	s := cond.String()
	if s != "($a OR $b)" {
		t.Errorf("Expected '($a OR $b)', got %s", s)
	}
}

func TestNotCondition(t *testing.T) {
	cond := &NotCondition{
		Condition: &StringCondition{StringID: "$a"},
	}

	// Test String()
	s := cond.String()
	if s != "(NOT $a)" {
		t.Errorf("Expected '(NOT $a)', got %s", s)
	}
}

func TestStringCondition(t *testing.T) {
	cond := &StringCondition{StringID: "$a"}

	// Test String()
	s := cond.String()
	if s != "$a" {
		t.Errorf("Expected '$a', got %s", s)
	}
}

func TestFileSizeCondition(t *testing.T) {
	cond := &FileSizeCondition{Operator: "<", Value: 1024}

	// Test String()
	s := cond.String()
	if s != "filesize < 1024" {
		t.Errorf("Expected 'filesize < 1024', got %s", s)
	}

	// Test Evaluate
	data := make([]byte, 512)
	if !cond.Evaluate(data) {
		t.Error("Expected true for 512 bytes")
	}

	data = make([]byte, 2048)
	if cond.Evaluate(data) {
		t.Error("Expected false for 2048 bytes")
	}
}

func TestEntryCondition(t *testing.T) {
	cond := &EntryCondition{}

	// Test String()
	s := cond.String()
	if s != "entrypoint" {
		t.Errorf("Expected 'entrypoint', got %s", s)
	}
}

func TestOffsetCondition(t *testing.T) {
	cond := &OffsetCondition{StringID: "$a", Offset: 100}

	// Test String()
	s := cond.String()
	if s != "@$a == 100" {
		t.Errorf("Expected '@$a == 100', got %s", s)
	}
}

func TestParseYARACondition(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		wantErr   bool
	}{
		{"true", "true", false},
		{"simple", "$a", false},
		{"complex", "($a and $b) or $c", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYARACondition(tt.condition)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseYARACondition() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHexToBytes(t *testing.T) {
	tests := []struct {
		name    string
		hex     string
		want    []byte
		wantErr bool
	}{
		{"valid", "4142", []byte{0x41, 0x42}, false},
		{"with spaces", "41 42 43", []byte{0x41, 0x42, 0x43}, false},
		{"invalid", "ZZZZ", nil, true},
		{"odd length", "414", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hexToBytes(tt.hex)
			if (err != nil) != tt.wantErr {
				t.Errorf("hexToBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !matchBytes(got, tt.want) {
				t.Errorf("hexToBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchBytes(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{"equal", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"different length", []byte{1, 2}, []byte{1, 2, 3}, false},
		{"different values", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchBytes(tt.a, tt.b); got != tt.want {
				t.Errorf("matchBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatCondition(t *testing.T) {
	cond := &AndCondition{
		Left:  &StringCondition{StringID: "$a"},
		Right: &StringCondition{StringID: "$b"},
	}

	s := FormatCondition(cond)
	if s != "($a AND $b)" {
		t.Errorf("Expected '($a AND $b)', got %s", s)
	}
}
