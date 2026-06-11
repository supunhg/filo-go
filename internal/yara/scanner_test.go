package yara

import (
	"testing"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	if scanner == nil {
		t.Fatal("Expected non-nil scanner")
	}

	if len(scanner.rules) != 0 {
		t.Errorf("Expected 0 rules, got %d", len(scanner.rules))
	}
}

func TestAddRule(t *testing.T) {
	scanner := NewScanner()
	rule := &Rule{
		Name:      "test_rule",
		Namespace: "test",
		Tags:      []string{"test"},
		Meta:      map[string]string{"author": "test"},
		Condition: "true",
		Strings: []YString{
			{Name: "a", TextStr: "hello"},
		},
	}

	scanner.AddRule(rule)

	if len(scanner.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(scanner.rules))
	}
}

func TestAddRuleSource(t *testing.T) {
	scanner := NewScanner()
	source := `rule test {
		strings:
			$a = "hello"
		condition:
			$a
	}`

	err := scanner.AddRuleSource(source)
	if err != nil {
		t.Fatalf("AddRuleSource() error = %v", err)
	}

	if len(scanner.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(scanner.rules))
	}
}

func TestAddRuleSourceMultiple(t *testing.T) {
	scanner := NewScanner()
	source := `rule rule1 {
		condition:
			true
	}
	rule rule2 {
		condition:
			true
	}`

	err := scanner.AddRuleSource(source)
	if err != nil {
		t.Fatalf("AddRuleSource() error = %v", err)
	}

	if len(scanner.rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(scanner.rules))
	}
}

func TestScan(t *testing.T) {
	scanner := NewScanner()
	rule := &Rule{
		Name:      "test_rule",
		Namespace: "test",
		Condition: "true",
		Strings: []YString{
			{Name: "a", TextStr: "hello"},
		},
	}

	scanner.AddRule(rule)

	data := []byte("hello world")
	result := scanner.Scan(data, "test.txt")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.FileName != "test.txt" {
		t.Errorf("Expected filename 'test.txt', got '%s'", result.FileName)
	}

	if result.RuleCount != 1 {
		t.Errorf("Expected 1 rule, got %d", result.RuleCount)
	}
}

func TestScanNoMatches(t *testing.T) {
	scanner := NewScanner()
	rule := &Rule{
		Name:      "test_rule",
		Condition: "$a",
		Strings: []YString{
			{Name: "a", TextStr: "hello"},
		},
	}

	scanner.AddRule(rule)

	data := []byte("world")
	result := scanner.Scan(data, "test.txt")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if len(result.Matches) != 0 {
		t.Errorf("Expected 0 matches, got %d", len(result.Matches))
	}
}

func TestScanWithHexStrings(t *testing.T) {
	scanner := NewScanner()
	rule := &Rule{
		Name:      "test_rule",
		Condition: "true",
		Strings: []YString{
			{Name: "a", HexStr: "{ 89 50 4E 47 }"},
		},
	}

	scanner.AddRule(rule)

	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x00, 0x00}
	result := scanner.Scan(data, "test.bin")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if len(result.Matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(result.Matches))
	}
}

func TestScanWithNamespace(t *testing.T) {
	scanner := NewScanner()
	rule := &Rule{
		Name:      "test_rule",
		Namespace: "malware",
		Condition: "true",
		Strings: []YString{
			{Name: "a", TextStr: "malware"},
		},
	}

	scanner.AddRule(rule)

	data := []byte("malware detected")
	result := scanner.Scan(data, "test.txt")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if len(result.Matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(result.Matches))
	}

	if result.Matches[0].Namespace != "malware" {
		t.Errorf("Expected namespace 'malware', got '%s'", result.Matches[0].Namespace)
	}
}

func TestScanWithTags(t *testing.T) {
	scanner := NewScanner()
	rule := &Rule{
		Name:      "test_rule",
		Tags:      []string{"malware", "trojan"},
		Condition: "true",
		Strings: []YString{
			{Name: "a", TextStr: "trojan"},
		},
	}

	scanner.AddRule(rule)

	data := []byte("trojan detected")
	result := scanner.Scan(data, "test.txt")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if len(result.Matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(result.Matches))
	}

	if len(result.Matches[0].Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(result.Matches[0].Tags))
	}
}

func TestScanWithMeta(t *testing.T) {
	scanner := NewScanner()
	rule := &Rule{
		Name:      "test_rule",
		Meta:      map[string]string{"author": "test", "version": "1.0"},
		Condition: "true",
		Strings: []YString{
			{Name: "a", TextStr: "test"},
		},
	}

	scanner.AddRule(rule)

	data := []byte("test data")
	result := scanner.Scan(data, "test.txt")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if len(result.Matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(result.Matches))
	}

	if result.Matches[0].Meta["author"] != "test" {
		t.Errorf("Expected author 'test', got '%s'", result.Matches[0].Meta["author"])
	}
}

func TestMatchRuleTrue(t *testing.T) {
	rule := &Rule{
		Name:      "test_rule",
		Condition: "true",
	}

	data := []byte("test")
	match := matchRule(data, rule)

	if match == nil {
		t.Fatal("Expected non-nil match")
	}
}

func TestMatchRuleFalse(t *testing.T) {
	rule := &Rule{
		Name:      "test_rule",
		Condition: "false",
		Strings: []YString{
			{Name: "a", TextStr: "hello"},
		},
	}

	data := []byte("world")
	match := matchRule(data, rule)

	if match != nil {
		t.Error("Expected nil match")
	}
}

func TestMatchRuleAnyOf(t *testing.T) {
	rule := &Rule{
		Name:      "test_rule",
		Condition: "any of them",
		Strings: []YString{
			{Name: "a", TextStr: "hello"},
			{Name: "b", TextStr: "world"},
		},
	}

	data := []byte("hello")
	match := matchRule(data, rule)

	if match == nil {
		t.Fatal("Expected non-nil match")
	}

	if len(match.Strings) != 1 {
		t.Errorf("Expected 1 matched string, got %d", len(match.Strings))
	}
}

func TestMatchRuleAllOf(t *testing.T) {
	rule := &Rule{
		Name:      "test_rule",
		Condition: "all of them",
		Strings: []YString{
			{Name: "a", TextStr: "hello"},
			{Name: "b", TextStr: "world"},
		},
	}

	data := []byte("hello world")
	match := matchRule(data, rule)

	if match == nil {
		t.Fatal("Expected non-nil match")
	}

	if len(match.Strings) != 2 {
		t.Errorf("Expected 2 matched strings, got %d", len(match.Strings))
	}
}

func TestMatchRuleFilesize(t *testing.T) {
	rule := &Rule{
		Name:      "test_rule",
		Condition: "filesize < 1024",
	}

	data := make([]byte, 512)
	match := matchRule(data, rule)

	if match == nil {
		t.Fatal("Expected non-nil match")
	}
}

func TestContainsBytesText(t *testing.T) {
	data := []byte("hello world")
	pattern := "hello"

	if !containsBytes(data, pattern) {
		t.Error("Expected true")
	}

	pattern = "world"
	if !containsBytes(data, pattern) {
		t.Error("Expected true")
	}

	pattern = "test"
	if containsBytes(data, pattern) {
		t.Error("Expected false")
	}
}

func TestContainsBytesHex(t *testing.T) {
	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x00, 0x00}
	pattern := "{ 89 50 4E 47 }"

	if !containsBytes(data, pattern) {
		t.Error("Expected true")
	}

	pattern = "{ 00 00 }"
	if !containsBytes(data, pattern) {
		t.Error("Expected true")
	}

	pattern = "{ FF FF }"
	if containsBytes(data, pattern) {
		t.Error("Expected false")
	}
}

func TestContainsBytesInvalidHex(t *testing.T) {
	data := []byte{0x89, 0x50}
	pattern := "{ ZZZ }"

	if containsBytes(data, pattern) {
		t.Error("Expected false for invalid hex")
	}
}

func TestContainsBytesOddHex(t *testing.T) {
	data := []byte{0x89, 0x50}
	pattern := "{ 89 5 }"

	if containsBytes(data, pattern) {
		t.Error("Expected false for odd length hex")
	}
}

func TestBytesContains(t *testing.T) {
	data := []byte("hello world")
	pattern := []byte("hello")

	if !bytesContains(data, pattern) {
		t.Error("Expected true")
	}

	pattern = []byte("world")
	if !bytesContains(data, pattern) {
		t.Error("Expected true")
	}

	pattern = []byte("test")
	if bytesContains(data, pattern) {
		t.Error("Expected false")
	}
}

func TestParseRuleSource(t *testing.T) {
	source := `rule test {
		strings:
			$a = "hello"
			$b = { 89 50 }
		condition:
			$a
	}`

	rules := parseRuleSource(source)
	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]
	if rule.Name != "test" {
		t.Errorf("Expected name 'test', got '%s'", rule.Name)
	}

	if len(rule.Strings) != 2 {
		t.Errorf("Expected 2 strings, got %d", len(rule.Strings))
	}

	if rule.Condition != "$a" {
		t.Errorf("Expected condition '$a', got '%s'", rule.Condition)
	}
}

func TestParseRuleSourceWithNamespace(t *testing.T) {
	source := `rule test:malware {
		condition:
			true
	}`

	rules := parseRuleSource(source)
	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	if rules[0].Namespace != "malware" {
		t.Errorf("Expected namespace 'malware', got '%s'", rules[0].Namespace)
	}
}

func TestParseRuleSourceEmpty(t *testing.T) {
	source := ""
	rules := parseRuleSource(source)
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules, got %d", len(rules))
	}
}

func TestPrint(t *testing.T) {
	result := &Result{
		FileName:  "test.txt",
		RuleCount: 1,
		Matches: []MatchResult{
			{
				RuleName:  "test_rule",
				Namespace: "test",
				Tags:      []string{"malware"},
				Strings:   []string{"$a: hello"},
			},
		},
	}

	// This should not panic
	Print(result)
}

func TestPrintNoMatches(t *testing.T) {
	result := &Result{
		FileName:  "test.txt",
		RuleCount: 1,
		Matches:   []MatchResult{},
	}

	// This should not panic
	Print(result)
}

func TestPrintEmpty(t *testing.T) {
	result := &Result{
		FileName:  "test.txt",
		RuleCount: 0,
		Matches:   []MatchResult{},
	}

	// This should not panic
	Print(result)
}

func TestRegisterModule(t *testing.T) {
	scanner := NewScanner()

	peInfo := &PEInfo{
		NumberOfSections: 5,
		EntryPoint:       0x1000,
		Machine:          "x86_64",
		Subsystem:        "Windows CUI",
		Imports:          []string{"kernel32.dll", "user32.dll"},
		IsEXE:            true,
	}

	scanner.RegisterModule("pe", peInfo)

	if scanner.modules["pe"] == nil {
		t.Error("expected PE module to be registered")
	}
}

func TestSetVariable(t *testing.T) {
	scanner := NewScanner()

	scanner.SetVariable("filename", "test.exe")
	scanner.SetVariable("filesize", 1024)

	val, ok := scanner.GetVariable("filename")
	if !ok || val != "test.exe" {
		t.Errorf("expected filename 'test.exe', got %v", val)
	}

	val, ok = scanner.GetVariable("filesize")
	if !ok || val != 1024 {
		t.Errorf("expected filesize 1024, got %v", val)
	}
}

func TestGetVariableNonexistent(t *testing.T) {
	scanner := NewScanner()

	_, ok := scanner.GetVariable("nonexistent")
	if ok {
		t.Error("expected false for nonexistent variable")
	}
}

func TestRuleAddVariable(t *testing.T) {
	rule := &Rule{
		Name:      "test_rule",
		Condition: "true",
	}

	rule.AddVariable("os", "windows")
	rule.AddVariable("arch", "x86_64")

	if rule.Variables["os"] != "windows" {
		t.Errorf("expected os 'windows', got %v", rule.Variables["os"])
	}

	if rule.Variables["arch"] != "x86_64" {
		t.Errorf("expected arch 'x86_64', got %v", rule.Variables["arch"])
	}
}

func TestPEInfoStructure(t *testing.T) {
	pe := &PEInfo{
		NumberOfSections: 5,
		EntryPoint:       0x1000,
		Machine:          "x86_64",
		Subsystem:        "Windows CUI",
		Imports:          []string{"kernel32.dll"},
		DLLs:             []string{"kernel32.dll", "user32.dll"},
		IsDLL:            false,
		IsEXE:            true,
	}

	if pe.NumberOfSections != 5 {
		t.Errorf("expected 5 sections, got %d", pe.NumberOfSections)
	}

	if !pe.IsEXE {
		t.Error("expected IsEXE to be true")
	}
}

func TestELFInfoStructure(t *testing.T) {
	elf := &ELFInfo{
		Type:       "EXEC",
		Machine:    "x86_64",
		Bits:       64,
		EntryPoint: 0x400000,
		Sections:   10,
		Is64bit:    true,
	}

	if elf.Bits != 64 {
		t.Errorf("expected 64 bits, got %d", elf.Bits)
	}

	if !elf.Is64bit {
		t.Error("expected Is64bit to be true")
	}
}

func TestMachOInfoStructure(t *testing.T) {
	macho := &MachOInfo{
		Type:    "MH_EXECUTE",
		CPU:     "x86_64",
		Bits:    64,
		IsFat:   false,
		Is64bit: true,
	}

	if macho.Type != "MH_EXECUTE" {
		t.Errorf("expected type MH_EXECUTE, got %s", macho.Type)
	}
}

func TestScannerWithModules(t *testing.T) {
	scanner := NewScanner()

	// Register PE module
	peInfo := &PEInfo{
		NumberOfSections: 3,
		IsEXE:            true,
	}
	scanner.RegisterModule("pe", peInfo)

	// Add rule that uses module info
	rule := &Rule{
		Name:      "pe_exe_rule",
		Condition: "true",
		Strings: []YString{
			{Name: "a", TextStr: "MZ"},
		},
	}
	scanner.AddRule(rule)

	data := []byte("MZ test data")
	result := scanner.Scan(data, "test.exe")

	if len(result.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(result.Matches))
	}
}

func TestScannerWithVariables(t *testing.T) {
	scanner := NewScanner()

	// Set variables
	scanner.SetVariable("min_size", 100)
	scanner.SetVariable("max_size", 10000)

	// Add rule
	rule := &Rule{
		Name:      "size_rule",
		Condition: "true",
		Strings: []YString{
			{Name: "a", TextStr: "test"},
		},
	}
	scanner.AddRule(rule)

	data := []byte("test data")
	result := scanner.Scan(data, "test.bin")

	if len(result.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(result.Matches))
	}
}
