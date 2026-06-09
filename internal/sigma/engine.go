package sigma

import (
	"fmt"
	"strings"
)

// Rule represents a Sigma detection rule.
type Rule struct {
	Title          string    `json:"title"`
	ID             string    `json:"id"`
	Status         string    `json:"status"`
	Description    string    `json:"description"`
	Author         string    `json:"author"`
	Date           string    `json:"date"`
	Tags           []string  `json:"tags"`
	Logsource      Logsource `json:"logsource"`
	Detection      Detection `json:"detection"`
	Condition      string    `json:"condition"`
	Falsepositives []string  `json:"falsepositives"`
	Level          string    `json:"level"`
}

// Logsource specifies the log source.
type Logsource struct {
	Category string `json:"category"`
	Product  string `json:"product"`
	Service  string `json:"service"`
}

// Detection specifies the detection logic.
type Detection struct {
	Keywords  []string          `json:"keywords"`
	Selection map[string]string `json:"selection"`
	Filter    map[string]string `json:"filter,omitempty"`
}

// Match represents a rule match.
type Match struct {
	Rule     *Rule    `json:"rule"`
	Matched  bool     `json:"matched"`
	Evidence []string `json:"evidence"`
}

// Engine evaluates Sigma rules.
type Engine struct {
	rules []*Rule
}

// NewEngine creates a new Sigma engine.
func NewEngine() *Engine {
	return &Engine{
		rules: []*Rule{},
	}
}

// LoadRule adds a rule to the engine.
func (e *Engine) LoadRule(rule *Rule) {
	e.rules = append(e.rules, rule)
}

// LoadRules adds multiple rules.
func (e *Engine) LoadRules(rules []*Rule) {
	e.rules = append(e.rules, rules...)
}

// Scan evaluates all rules against data.
func (e *Engine) Scan(data []byte, fileName string) []*Match {
	var matches []*Match

	for _, rule := range e.rules {
		match := e.evaluateRule(rule, data)
		if match.Matched {
			matches = append(matches, match)
		}
	}

	return matches
}

func (e *Engine) evaluateRule(rule *Rule, data []byte) *Match {
	match := &Match{
		Rule:     rule,
		Matched:  false,
		Evidence: []string{},
	}

	text := string(data)

	// Check keywords
	for _, keyword := range rule.Detection.Keywords {
		if strings.Contains(text, keyword) {
			match.Matched = true
			match.Evidence = append(match.Evidence, fmt.Sprintf("Keyword: %s", keyword))
		}
	}

	// Check selection patterns
	for field, pattern := range rule.Detection.Selection {
		if strings.Contains(text, pattern) {
			match.Matched = true
			match.Evidence = append(match.Evidence, fmt.Sprintf("%s: %s", field, pattern))
		}
	}

	return match
}

// LoadBuiltinRules loads common detection rules.
func (e *Engine) LoadBuiltinRules() {
	// Suspicious process execution
	e.LoadRule(&Rule{
		Title:       "Suspicious Process Execution",
		ID:          "builtin-001",
		Description: "Detects suspicious process execution patterns",
		Level:       "high",
		Tags:        []string{"attack.execution"},
		Logsource:   Logsource{Category: "process_creation"},
		Detection: Detection{
			Keywords: []string{
				"cmd.exe /c", "powershell -enc", "wmic process call create",
				"regsvr32 /s /n /u /i:", "certutil -urlcache",
				"bitsadmin /transfer", "mshta http",
			},
		},
	})

	// Persistence mechanisms
	e.LoadRule(&Rule{
		Title:       "Persistence Mechanism",
		ID:          "builtin-002",
		Description: "Detects common persistence mechanisms",
		Level:       "high",
		Tags:        []string{"attack.persistence"},
		Logsource:   Logsource{Category: "registry"},
		Detection: Detection{
			Keywords: []string{
				"CurrentVersion\\Run", "CurrentVersion\\RunOnce",
				"Services\\", "ScheduledTasks",
			},
		},
	})

	// Credential access
	e.LoadRule(&Rule{
		Title:       "Credential Access Attempt",
		ID:          "builtin-003",
		Description: "Detects credential access attempts",
		Level:       "critical",
		Tags:        []string{"attack.credential_access"},
		Logsource:   Logsource{Category: "process_creation"},
		Detection: Detection{
			Keywords: []string{
				"mimikatz", "lsass", "sekurlsa", "kerberos::list",
				"procdump", "comsvcs.dll MiniDump",
			},
		},
	})

	// Lateral movement
	e.LoadRule(&Rule{
		Title:       "Lateral Movement Indicator",
		ID:          "builtin-004",
		Description: "Detects lateral movement indicators",
		Level:       "high",
		Tags:        []string{"attack.lateral_movement"},
		Detection: Detection{
			Keywords: []string{
				"PsExec", "WinRM", "SSH", "RDP",
				"SMB", "WMI", "DCOM",
			},
		},
	})
}

// Print displays Sigma scan results.
func PrintMatches(matches []*Match, fileName string) {
	fmt.Println()
	fmt.Printf("  Sigma Scan: %s\n", fileName)
	fmt.Printf("  Rules Loaded: %d\n", len(matches))
	fmt.Println()

	if len(matches) == 0 {
		fmt.Println("  No matches found")
	} else {
		fmt.Printf("  Found %d match(es):\n\n", len(matches))
		for _, m := range matches {
			fmt.Printf("    Rule: %s\n", m.Rule.Title)
			fmt.Printf("    Level: %s\n", m.Rule.Level)
			fmt.Printf("    ID: %s\n", m.Rule.ID)
			if len(m.Evidence) > 0 {
				fmt.Println("    Evidence:")
				for _, e := range m.Evidence {
					fmt.Printf("      - %s\n", e)
				}
			}
			fmt.Println()
		}
	}
}
