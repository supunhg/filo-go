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
