package yara

import (
	"fmt"
	"strings"
)

// Result holds YARA scan results.
type Result struct {
	FileName string        `json:"file_name"`
	Matches  []MatchResult `json:"matches"`
	RuleCount int          `json:"rule_count"`
}

// MatchResult represents a single rule match.
type MatchResult struct {
	RuleName  string            `json:"rule_name"`
	Namespace string            `json:"namespace"`
	Tags      []string          `json:"tags,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
	Strings   []string          `json:"strings,omitempty"`
}

// Rule represents a simplified YARA rule.
type Rule struct {
	Name      string
	Namespace string
	Tags      []string
	Meta      map[string]string
	Condition string
	Strings   []YString
}

// YString represents a YARA string definition.
type YString struct {
	Name    string
	HexStr  string
	TextStr string
	Offset  int
}

// Scanner performs YARA-like scanning.
type Scanner struct {
	rules []*Rule
}

// NewScanner creates a new YARA scanner.
func NewScanner() *Scanner {
	return &Scanner{
		rules: []*Rule{},
	}
}

// AddRule adds a rule to the scanner.
func (s *Scanner) AddRule(rule *Rule) {
	s.rules = append(s.rules, rule)
}

// AddRuleSource parses and adds a rule from source text.
func (s *Scanner) AddRuleSource(source string) error {
	rules := parseRuleSource(source)
	s.rules = append(s.rules, rules...)
	return nil
}

// Scan scans data against all rules.
func (s *Scanner) Scan(data []byte, fileName string) *Result {
	result := &Result{
		FileName: fileName,
		Matches:  []MatchResult{},
	}

	for _, rule := range s.rules {
		match := matchRule(data, rule)
		if match != nil {
			result.Matches = append(result.Matches, *match)
		}
	}

	result.RuleCount = len(s.rules)
	return result
}

func matchRule(data []byte, rule *Rule) *MatchResult {
	match := &MatchResult{
		RuleName:  rule.Name,
		Namespace: rule.Namespace,
		Tags:      rule.Tags,
		Meta:      rule.Meta,
		Strings:   []string{},
	}

	matched := false

	// Check strings
	for _, ys := range rule.Strings {
		var searchPattern string
		if ys.HexStr != "" {
			searchPattern = ys.HexStr
		} else if ys.TextStr != "" {
			searchPattern = ys.TextStr
		}

		if searchPattern != "" {
			if containsBytes(data, searchPattern) {
				match.Strings = append(match.Strings, fmt.Sprintf("$%s: %s", ys.Name, searchPattern))
				matched = true
			}
		}
	}

	// Simple condition evaluation
	if rule.Condition == "true" || rule.Condition == "" {
		matched = true
	} else if strings.Contains(rule.Condition, "any of") {
		matched = len(match.Strings) > 0
	} else if strings.Contains(rule.Condition, "all of") {
		matched = len(match.Strings) == len(rule.Strings)
	} else if strings.Contains(rule.Condition, "filesize") {
		matched = true // Simplified
	}

	if matched || (len(rule.Strings) == 0 && rule.Condition != "") {
		return match
	}

	if !matched {
		return nil
	}

	return match
}

func containsBytes(data []byte, pattern string) bool {
	// Handle hex strings like { 89 50 4E 47 }
	if strings.HasPrefix(pattern, "{") && strings.HasSuffix(pattern, "}") {
		hexStr := strings.Trim(pattern, "{} ")
		hexStr = strings.ReplaceAll(hexStr, " ", "")
		if len(hexStr)%2 != 0 {
			return false
		}
		hexBytes := make([]byte, len(hexStr)/2)
		for i := 0; i < len(hexStr); i += 2 {
			var b byte
			for j := 0; j < 2; j++ {
				c := hexStr[i+j]
				switch {
				case c >= '0' && c <= '9':
					b = b*16 + (c - '0')
				case c >= 'a' && c <= 'f':
					b = b*16 + (c - 'a' + 10)
				case c >= 'A' && c <= 'F':
					b = b*16 + (c - 'A' + 10)
				default:
					return false
				}
			}
			hexBytes[i/2] = b
		}
		return bytesContains(data, hexBytes)
	}

	// Handle text strings
	return bytesContains(data, []byte(pattern))
}

// bytesContains checks if data contains pattern.
func bytesContains(data, pattern []byte) bool {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j, b := range pattern {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func parseRuleSource(source string) []*Rule {
	var rules []*Rule

	// Simple rule parser
	lines := strings.Split(source, "\n")
	var currentRule *Rule

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "rule ") {
			if currentRule != nil {
				rules = append(rules, currentRule)
			}
			parts := strings.SplitN(line[5:], ":", 2)
			name := strings.TrimSpace(parts[0])
			currentRule = &Rule{
				Name:   name,
				Meta:   map[string]string{},
				Strings: []YString{},
			}
			if len(parts) > 1 {
				currentRule.Namespace = strings.TrimSpace(parts[1])
			}
		} else if currentRule != nil {
			if strings.HasPrefix(line, "strings:") {
				// Parse strings section
			} else if strings.HasPrefix(line, "condition:") {
				condition := strings.TrimPrefix(line, "condition:")
				currentRule.Condition = strings.TrimSpace(condition)
			} else if strings.HasPrefix(line, "$") {
				// Parse string definition
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					name := strings.TrimPrefix(strings.TrimSpace(parts[0]), "$")
					value := strings.TrimSpace(parts[1])
					ys := YString{Name: name}
					if strings.HasPrefix(value, "{") {
						ys.HexStr = value
					} else {
						ys.TextStr = strings.Trim(value, "\"")
					}
					currentRule.Strings = append(currentRule.Strings, ys)
				}
			}
		}
	}

	if currentRule != nil {
		rules = append(rules, currentRule)
	}

	return rules
}

// Print displays YARA results.
func Print(r *Result) {
	fmt.Println()
	fmt.Printf("  YARA Scan: %s\n", r.FileName)
	fmt.Printf("  Rules Loaded: %d\n", r.RuleCount)
	fmt.Println()

	if len(r.Matches) == 0 {
		fmt.Println("  No matches found")
	} else {
		fmt.Printf("  Found %d match(es):\n\n", len(r.Matches))
		for _, m := range r.Matches {
			fmt.Printf("    Rule: %s\n", m.RuleName)
			if m.Namespace != "" {
				fmt.Printf("    Namespace: %s\n", m.Namespace)
			}
			if len(m.Tags) > 0 {
				fmt.Printf("    Tags: %s\n", strings.Join(m.Tags, ", "))
			}
			if len(m.Strings) > 0 {
				fmt.Println("    Matched strings:")
				for _, s := range m.Strings {
					fmt.Printf("      %s\n", s)
				}
			}
			fmt.Println()
		}
	}
}
