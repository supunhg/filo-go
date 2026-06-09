package cli

import (
	"fmt"
	"strings"
)

// ProgressBar displays a progress bar in the terminal.
type ProgressBar struct {
	total    int
	current  int
	width    int
	prefix   string
	showPct  bool
	done     chan bool
}

// NewProgressBar creates a new progress bar.
func NewProgressBar(total int, prefix string) *ProgressBar {
	return &ProgressBar{
		total:   total,
		current: 0,
		width:   40,
		prefix:  prefix,
		showPct: true,
		done:    make(chan bool),
	}
}

// Update updates the progress bar.
func (p *ProgressBar) Update(current int) {
	p.current = current
	p.render()
}

// Increment increments the progress bar by 1.
func (p *ProgressBar) Increment() {
	p.current++
	p.render()
}

// Finish completes the progress bar.
func (p *ProgressBar) Finish() {
	p.current = p.total
	p.render()
	fmt.Println()
}

func (p *ProgressBar) render() {
	if p.total == 0 {
		return
	}

	percent := float64(p.current) / float64(p.total) * 100
	filled := int(float64(p.width) * float64(p.current) / float64(p.total))

	// Build bar
	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)

	// Format output
	fmt.Printf("\r  %s [%s] %3.0f%% (%d/%d)", p.prefix, bar, percent, p.current, p.total)
}

// Spinner displays a spinning animation.
type Spinner struct {
	message string
	frames  []string
	current int
	done    chan bool
}

// NewSpinner creates a new spinner.
func NewSpinner(message string) *Spinner {
	return &Spinner{
		message: message,
		frames:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		current: 0,
		done:    make(chan bool),
	}
}

// Start starts the spinner animation.
func (s *Spinner) Start() {
	go func() {
		for {
			select {
			case <-s.done:
				return
			default:
				fmt.Printf("\r  %s %s", s.frames[s.current], s.message)
				s.current = (s.current + 1) % len(s.frames)
				sleep(100)
			}
		}
	}()
}

// Stop stops the spinner.
func (s *Spinner) Stop() {
	s.done <- true
	fmt.Printf("\r  ✓ %s\n", s.message)
}

// UpdateMessage updates the spinner message.
func (s *Spinner) UpdateMessage(msg string) {
	s.message = msg
}

// Table displays formatted table output.
type Table struct {
	headers []string
	rows    [][]string
	widths  []int
}

// NewTable creates a new table.
func NewTable(headers ...string) *Table {
	t := &Table{
		headers: headers,
		widths:  make([]int, len(headers)),
	}

	// Initialize widths from headers
	for i, h := range headers {
		t.widths[i] = len(h)
	}

	return t
}

// AddRow adds a row to the table.
func (t *Table) AddRow(row ...string) {
	t.rows = append(t.rows, row)

	// Update widths
	for i, cell := range row {
		if i < len(t.widths) && len(cell) > t.widths[i] {
			t.widths[i] = len(cell)
		}
	}
}

// Print prints the table.
func (t *Table) Print() {
	// Print header
	fmt.Print("  ")
	for i, h := range t.headers {
		fmt.Printf("%-*s  ", t.widths[i], h)
	}
	fmt.Println()

	// Print separator
	fmt.Print("  ")
	for _, w := range t.widths {
		fmt.Print(strings.Repeat("─", w+2))
	}
	fmt.Println()

	// Print rows
	for _, row := range t.rows {
		fmt.Print("  ")
		for i, cell := range row {
			if i < len(t.widths) {
				fmt.Printf("%-*s  ", t.widths[i], cell)
			}
		}
		fmt.Println()
	}
}

// PrintHeader prints a styled header.
func PrintHeader(title string, width int) {
	if width == 0 {
		width = 60
	}

	fmt.Println()
	fmt.Printf("  %s\n", strings.Repeat("═", width))
	fmt.Printf("  %s\n", title)
	fmt.Printf("  %s\n", strings.Repeat("═", width))
	fmt.Println()
}

// PrintSection prints a section header.
func PrintSection(title string) {
	fmt.Printf("\n  %s\n", title)
	fmt.Printf("  %s\n", strings.Repeat("─", len(title)+2))
}

// PrintKeyValue prints a key-value pair.
func PrintKeyValue(key string, value interface{}) {
	fmt.Printf("  %-20s %v\n", key+":", value)
}

// PrintSuccess prints a success message.
func PrintSuccess(msg string) {
	fmt.Printf("  ✓ %s\n", msg)
}

// PrintWarning prints a warning message.
func PrintWarning(msg string) {
	fmt.Printf("  ⚠  %s\n", msg)
}

// PrintError prints an error message.
func PrintError(msg string) {
	fmt.Printf("  ✗ %s\n", msg)
}

// PrintInfo prints an info message.
func PrintInfo(msg string) {
	fmt.Printf("  ℹ  %s\n", msg)
}

// PrintBanner prints the application banner.
func PrintBanner() {
	banner := `
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   ███████╗██████╗ ██╗     ██╗████████╗                   ║
  ║   ██╔════╝██╔══██╗██║     ██║╚══██╔══╝                   ║
  ║   █████╗  ██████╔╝██║     ██║   ██║                      ║
  ║   ██╔══╝  ██╔══██╗██║     ██║   ██║                      ║
  ║   ███████╗██║  ██║███████╗██║   ██║                      ║
  ║   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝                      ║
  ║                                                           ║
  ║   Forensic Intelligence & Learning Operator              ║
  ║   v0.2.0                                                 ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
`
	fmt.Print(banner)
}

// PrintEntropyBar prints an entropy bar with color.
func PrintEntropyBar(entropy float64, width int) {
	if width == 0 {
		width = 40
	}

	// Scale to width
	scaled := entropy / 8.0 * float64(width)
	filled := int(scaled)

	// Choose color based on entropy
	var color string
	switch {
	case entropy < 2.0:
		color = "\033[32m" // Green
	case entropy < 4.0:
		color = "\033[36m" // Cyan
	case entropy < 6.0:
		color = "\033[33m" // Yellow
	case entropy < 7.0:
		color = "\033[35m" // Magenta
	default:
		color = "\033[31m" // Red
	}

	reset := "\033[0m"

	// Build bar
	bar := color + strings.Repeat("█", filled) + reset + strings.Repeat("░", width-filled)
	fmt.Printf("  %s %.2f\n", bar, entropy)
}

func sleep(ms int) {
	// Simple sleep without time import
	for i := 0; i < ms*1000; i++ {
		_ = i
	}
}
