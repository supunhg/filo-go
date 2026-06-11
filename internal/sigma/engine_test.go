package sigma

import (
	"testing"
)

func TestNewEngine(t *testing.T) {
	engine := NewEngine()
	if engine == nil {
		t.Error("Expected non-nil engine")
	}
}

func TestLoadRule(t *testing.T) {
	engine := NewEngine()

	rule := &Rule{
		Title: "Test Rule",
		ID:    "test-001",
		Level: "medium",
	}

	engine.LoadRule(rule)

	if len(engine.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(engine.rules))
	}
}

func TestLoadRules(t *testing.T) {
	engine := NewEngine()

	rules := []*Rule{
		{Title: "Rule 1", ID: "test-001"},
		{Title: "Rule 2", ID: "test-002"},
	}

	engine.LoadRules(rules)

	if len(engine.rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(engine.rules))
	}
}

func TestScan(t *testing.T) {
	engine := NewEngine()

	// Load builtin rules
	engine.LoadBuiltinRules()

	// Test with data that might match
	data := []byte("This file contains suspicious activity")
	matches := engine.Scan(data, "test.txt")

	// Just test that it doesn't crash
	_ = matches
}

func TestLoadBuiltinRules(t *testing.T) {
	engine := NewEngine()
	engine.LoadBuiltinRules()

	if len(engine.rules) == 0 {
		t.Error("Expected at least one builtin rule")
	}
}

func TestScanWithKeywordMatch(t *testing.T) {
	engine := NewEngine()

	// Add a rule with a specific keyword
	engine.LoadRule(&Rule{
		Title:       "Test Rule",
		ID:          "test-001",
		Description: "Test rule for keyword matching",
		Level:       "high",
		Detection: Detection{
			Keywords: []string{"malware", "suspicious"},
		},
	})

	// Test with matching data
	data := []byte("This file contains malware signatures")
	matches := engine.Scan(data, "test.txt")

	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}

	if matches[0].Rule.ID != "test-001" {
		t.Errorf("Expected rule ID test-001, got %s", matches[0].Rule.ID)
	}
}

func TestScanWithSelectionMatch(t *testing.T) {
	engine := NewEngine()

	// Add a rule with selection patterns
	engine.LoadRule(&Rule{
		Title:       "Test Selection Rule",
		ID:          "test-002",
		Description: "Test rule for selection matching",
		Level:       "medium",
		Detection: Detection{
			Selection: map[string]string{
				"CommandLine": "cmd.exe /c",
			},
		},
	})

	// Test with matching data
	data := []byte("Process executed: cmd.exe /c whoami")
	matches := engine.Scan(data, "test.txt")

	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}
}

func TestScanWithNoMatch(t *testing.T) {
	engine := NewEngine()

	// Add a rule
	engine.LoadRule(&Rule{
		Title:       "Test Rule",
		ID:          "test-003",
		Description: "Test rule",
		Level:       "low",
		Detection: Detection{
			Keywords: []string{"nonexistent_keyword"},
		},
	})

	// Test with non-matching data
	data := []byte("This is clean data")
	matches := engine.Scan(data, "test.txt")

	if len(matches) != 0 {
		t.Errorf("Expected 0 matches, got %d", len(matches))
	}
}

func TestScanWithMultipleRules(t *testing.T) {
	engine := NewEngine()

	// Add multiple rules
	engine.LoadRule(&Rule{
		Title: "Rule 1",
		ID:    "test-004",
		Level: "high",
		Detection: Detection{
			Keywords: []string{"malware"},
		},
	})

	engine.LoadRule(&Rule{
		Title: "Rule 2",
		ID:    "test-005",
		Level: "medium",
		Detection: Detection{
			Keywords: []string{"suspicious"},
		},
	})

	// Test with data matching both rules
	data := []byte("This malware is suspicious")
	matches := engine.Scan(data, "test.txt")

	if len(matches) != 2 {
		t.Errorf("Expected 2 matches, got %d", len(matches))
	}
}

func TestScanWithMultipleKeywords(t *testing.T) {
	engine := NewEngine()

	// Add a rule with multiple keywords
	engine.LoadRule(&Rule{
		Title: "Multi Keyword Rule",
		ID:    "test-006",
		Level: "high",
		Detection: Detection{
			Keywords: []string{"keyword1", "keyword2", "keyword3"},
		},
	})

	// Test with data matching one keyword
	data := []byte("This contains keyword2 in it")
	matches := engine.Scan(data, "test.txt")

	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}

	// Verify evidence
	if len(matches[0].Evidence) != 1 {
		t.Errorf("Expected 1 evidence, got %d", len(matches[0].Evidence))
	}
}

func TestScanBuiltinRules(t *testing.T) {
	engine := NewEngine()
	engine.LoadBuiltinRules()

	tests := []struct {
		name     string
		data     string
		expected int
	}{
		{"cmd.exe", "Process: cmd.exe /c whoami", 1},
		{"powershell", "Process: powershell -enc Base64String", 1},
		{"mimikatz", "Found mimikatz in memory", 1},
		{"clean", "This is clean data", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := engine.Scan([]byte(tt.data), "test.txt")
			if len(matches) != tt.expected {
				t.Errorf("Expected %d matches, got %d", tt.expected, len(matches))
			}
		})
	}
}

func TestEvaluateRuleStructure(t *testing.T) {
	engine := NewEngine()

	rule := &Rule{
		Title:       "Structured Rule",
		ID:          "test-007",
		Description: "A rule with full structure",
		Level:       "critical",
		Tags:        []string{"attack.execution", "attack.persistence"},
		Logsource:   Logsource{Category: "process_creation", Product: "windows"},
		Detection: Detection{
			Keywords:  []string{"test_keyword"},
			Selection: map[string]string{"field": "value"},
		},
		Falsepositives: []string{"legitimate software"},
	}

	engine.LoadRule(rule)

	data := []byte("test_keyword present")
	matches := engine.Scan(data, "test.txt")

	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}

	if matches[0].Rule.Level != "critical" {
		t.Errorf("Expected level critical, got %s", matches[0].Rule.Level)
	}
}

func TestPrintMatchesEmpty(t *testing.T) {
	// Test PrintMatches with no matches
	PrintMatches([]*Match{}, "test.txt")
}

func TestPrintMatchesWithData(t *testing.T) {
	// Test PrintMatches with matches
	matches := []*Match{
		{
			Rule: &Rule{
				Title: "Test Rule",
				ID:    "test-001",
				Level: "high",
			},
			Matched:  true,
			Evidence: []string{"Keyword: test"},
		},
	}
	PrintMatches(matches, "test.txt")
}
