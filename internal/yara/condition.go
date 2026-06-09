package yara

import (
	"fmt"
	"strconv"
	"strings"
)

// Condition represents a YARA condition
type Condition interface {
	Evaluate(data []byte) bool
	String() string
}

// AndCondition represents an AND condition
type AndCondition struct {
	Left  Condition
	Right Condition
}

func (c *AndCondition) Evaluate(data []byte) bool {
	return c.Left.Evaluate(data) && c.Right.Evaluate(data)
}

func (c *AndCondition) String() string {
	return fmt.Sprintf("(%s AND %s)", c.Left, c.Right)
}

// OrCondition represents an OR condition
type OrCondition struct {
	Left  Condition
	Right Condition
}

func (c *OrCondition) Evaluate(data []byte) bool {
	return c.Left.Evaluate(data) || c.Right.Evaluate(data)
}

func (c *OrCondition) String() string {
	return fmt.Sprintf("(%s OR %s)", c.Left, c.Right)
}

// NotCondition represents a NOT condition
type NotCondition struct {
	Condition Condition
}

func (c *NotCondition) Evaluate(data []byte) bool {
	return !c.Condition.Evaluate(data)
}

func (c *NotCondition) String() string {
	return fmt.Sprintf("(NOT %s)", c.Condition)
}

// StringCondition represents a string match condition
type StringCondition struct {
	StringID string
}

func (c *StringCondition) Evaluate(data []byte) bool {
	// This is a placeholder - real implementation would check the string
	return false
}

func (c *StringCondition) String() string {
	return c.StringID
}

// FileSizeCondition represents a file size condition
type FileSizeCondition struct {
	Operator string
	Value    int64
}

func (c *FileSizeCondition) Evaluate(data []byte) bool {
	size := int64(len(data))
	switch c.Operator {
	case "<":
		return size < c.Value
	case "<=":
		return size <= c.Value
	case ">":
		return size > c.Value
	case ">=":
		return size >= c.Value
	case "==":
		return size == c.Value
	default:
		return false
	}
}

func (c *FileSizeCondition) String() string {
	return fmt.Sprintf("filesize %s %d", c.Operator, c.Value)
}

// EntryCondition represents an entrypoint condition
type EntryCondition struct {
	Offset int64
}

func (c *EntryCondition) Evaluate(data []byte) bool {
	// This is a placeholder - real implementation would check entrypoint
	return false
}

func (c *EntryCondition) String() string {
	return "entrypoint"
}

// OffsetCondition represents an offset condition
type OffsetCondition struct {
	StringID string
	Offset   int64
}

func (c *OffsetCondition) Evaluate(data []byte) bool {
	// This is a placeholder - real implementation would check offset
	return false
}

func (c *OffsetCondition) String() string {
	return fmt.Sprintf("@%s == %d", c.StringID, c.Offset)
}

// ConditionParser parses YARA conditions
type ConditionParser struct {
	Pos    int
	Tokens []string
}

// ParseCondition parses a YARA condition string
func ParseCondition(conditionStr string) (Condition, error) {
	parser := &ConditionParser{
		Tokens: tokenizeCondition(conditionStr),
	}

	condition, err := parser.parseOr()
	if err != nil {
		return nil, err
	}

	return condition, nil
}

// tokenizeCondition tokenizes a condition string
func tokenizeCondition(condition string) []string {
	var tokens []string

	// Add spaces around parentheses and operators
	condition = strings.ReplaceAll(condition, "(", " ( ")
	condition = strings.ReplaceAll(condition, ")", " ) ")
	condition = strings.ReplaceAll(condition, "&&", " AND ")
	condition = strings.ReplaceAll(condition, "||", " OR ")
	condition = strings.ReplaceAll(condition, "!", " NOT ")

	for _, word := range strings.Fields(condition) {
		word = strings.TrimSpace(word)
		if word != "" {
			tokens = append(tokens, strings.ToUpper(word))
		}
	}

	return tokens
}

// parseOr parses an OR expression
func (p *ConditionParser) parseOr() (Condition, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	for p.Pos < len(p.Tokens) && p.Tokens[p.Pos] == "OR" {
		p.Pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &OrCondition{Left: left, Right: right}
	}

	return left, nil
}

// parseAnd parses an AND expression
func (p *ConditionParser) parseAnd() (Condition, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}

	for p.Pos < len(p.Tokens) && p.Tokens[p.Pos] == "AND" {
		p.Pos++
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &AndCondition{Left: left, Right: right}
	}

	return left, nil
}

// parseNot parses a NOT expression
func (p *ConditionParser) parseNot() (Condition, error) {
	if p.Pos < len(p.Tokens) && p.Tokens[p.Pos] == "NOT" {
		p.Pos++
		condition, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &NotCondition{Condition: condition}, nil
	}

	return p.parsePrimary()
}

// parsePrimary parses a primary expression
func (p *ConditionParser) parsePrimary() (Condition, error) {
	if p.Pos >= len(p.Tokens) {
		return nil, fmt.Errorf("unexpected end of condition")
	}

	token := p.Tokens[p.Pos]

	// Handle parentheses
	if token == "(" {
		p.Pos++
		condition, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.Pos >= len(p.Tokens) || p.Tokens[p.Pos] != ")" {
			return nil, fmt.Errorf("expected closing parenthesis")
		}
		p.Pos++
		return condition, nil
	}

	// Handle string identifiers ($1, $2, etc.)
	if strings.HasPrefix(token, "$") {
		p.Pos++
		return &StringCondition{StringID: token}, nil
	}

	// Handle filesize
	if token == "FILESIZE" {
		p.Pos++
		if p.Pos >= len(p.Tokens) {
			return nil, fmt.Errorf("expected operator after filesize")
		}
		operator := p.Tokens[p.Pos]
		p.Pos++
		if p.Pos >= len(p.Tokens) {
			return nil, fmt.Errorf("expected value after filesize operator")
		}
		value, err := strconv.ParseInt(p.Tokens[p.Pos], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid filesize value: %w", err)
		}
		p.Pos++
		return &FileSizeCondition{Operator: operator, Value: value}, nil
	}

	// Handle entrypoint
	if token == "ENTRYPOINT" {
		p.Pos++
		return &EntryCondition{}, nil
	}

	// Handle NOT
	if token == "NOT" {
		p.Pos++
		condition, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &NotCondition{Condition: condition}, nil
	}

	return nil, fmt.Errorf("unexpected token: %s", token)
}

// EvaluateCondition evaluates a condition against data
func EvaluateCondition(condition Condition, data []byte, matches []MatchResult) bool {
	// This is a simplified implementation
	// Real YARA would need to track string matches and evaluate conditions properly

	// For now, just return false as a placeholder
	return false
}

// ParseYARACondition parses a YARA rule condition
func ParseYARACondition(conditionStr string) (Condition, error) {
	// Clean up the condition string
	conditionStr = strings.TrimSpace(conditionStr)

	// Handle simple conditions
	if conditionStr == "true" {
		return &AndCondition{Left: &StringCondition{StringID: "$true"}, Right: &StringCondition{StringID: "$true"}}, nil
	}

	// Parse the condition
	return ParseCondition(conditionStr)
}

// EvaluateYARARule evaluates a YARA rule against data
func EvaluateYARARule(rule *Rule, data []byte) bool {
	if rule == nil || len(rule.Strings) == 0 {
		return false
	}

	// Find all string matches
	var matches []MatchResult
	for _, str := range rule.Strings {
		if str.HexStr != "" {
			// Parse hex string
			hexStr := strings.ReplaceAll(str.HexStr, " ", "")
			hexStr = strings.ReplaceAll(hexStr, "[", "")
			hexStr = strings.ReplaceAll(hexStr, "]", "")

			// Convert hex to bytes
			bytes, err := hexToBytes(hexStr)
			if err != nil {
				continue
			}

			// Find all occurrences
			for i := 0; i <= len(data)-len(bytes); i++ {
				if matchBytes(data[i:i+len(bytes)], bytes) {
					matches = append(matches, MatchResult{
						RuleName: rule.Name,
						Strings:  []string{str.Name},
					})
				}
			}
		} else if str.TextStr != "" {
			// Find text string
			offset := indexOf(data, []byte(str.TextStr))
			if offset != -1 {
				matches = append(matches, MatchResult{
					RuleName: rule.Name,
					Strings:  []string{str.Name},
				})
			}
		}
	}

	// If no matches found, rule doesn't match
	if len(matches) == 0 {
		return false
	}

	// Parse and evaluate the condition
	condition, err := ParseYARACondition(rule.Condition)
	if err != nil {
		// If we can't parse the condition, fall back to simple logic
		// If condition contains "AND", all strings must match
		if strings.Contains(rule.Condition, "AND") {
			// Check if all strings have matches
			matchedStrings := make(map[string]bool)
			for _, match := range matches {
				for _, s := range match.Strings {
					matchedStrings[s] = true
				}
			}

			for _, str := range rule.Strings {
				if !matchedStrings[str.Name] {
					return false
				}
			}
			return true
		}

		// If condition contains "OR", any string match is enough
		return true
	}

	// Evaluate the condition
	return EvaluateCondition(condition, data, matches)
}

// hexToBytes converts a hex string to bytes
func hexToBytes(hex string) ([]byte, error) {
	var bytes []byte
	hex = strings.ReplaceAll(hex, " ", "")
	for i := 0; i < len(hex); i += 2 {
		if i+2 > len(hex) {
			return nil, fmt.Errorf("invalid hex string")
		}

		b, err := strconv.ParseUint(hex[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}

		bytes = append(bytes, byte(b))
	}

	return bytes, nil
}

// matchBytes checks if two byte slices are equal
func matchBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// indexOf returns the index of the first occurrence of pattern in s
func indexOf(s, pattern []byte) int {
	for i := 0; i <= len(s)-len(pattern); i++ {
		if matchBytes(s[i:i+len(pattern)], pattern) {
			return i
		}
	}
	return -1
}

// FormatCondition formats a condition for display
func FormatCondition(condition Condition) string {
	return condition.String()
}
