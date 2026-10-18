// Package term decides whether terminal output may use ANSI colors and
// provides the color codes used across filo's human-readable output.
//
// Colors are enabled only when stdout is an interactive terminal, unless the
// user overrides that with --color or the NO_COLOR / FORCE_COLOR conventions
// (https://no-color.org).
package term

import (
	"fmt"
	"os"
	"strings"
	"sync"

	xterm "golang.org/x/term"
)

// Mode selects how color output is decided.
type Mode int

const (
	// Auto enables color when stdout is a terminal and no env var disables it.
	Auto Mode = iota
	// Always forces color on.
	Always
	// Never forces color off.
	Never
)

// ANSI escape sequences. Use them only through C so they disappear when color
// is disabled.
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Gray    = "\033[90m"
	BrRed   = "\033[91m"
	BrGreen = "\033[92m"
	BrYel   = "\033[93m"
)

var (
	mu      sync.RWMutex
	mode    = Auto
	once    sync.Once
	autoVal bool
)

// ParseMode converts a --color flag value into a Mode.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return Auto, nil
	case "always", "on", "true", "yes":
		return Always, nil
	case "never", "off", "false", "no":
		return Never, nil
	}
	return Auto, fmt.Errorf("invalid color mode %q (want auto, always or never)", s)
}

// SetMode overrides automatic color detection.
func SetMode(m Mode) {
	mu.Lock()
	mode = m
	mu.Unlock()
	if m == Always {
		enableVirtualTerminal()
	}
}

// Enabled reports whether color output is currently enabled.
func Enabled() bool {
	mu.RLock()
	m := mode
	mu.RUnlock()
	switch m {
	case Always:
		return true
	case Never:
		return false
	}
	once.Do(func() { autoVal = detect() })
	return autoVal
}

// C returns code when color is enabled and "" otherwise.
func C(code string) string {
	if Enabled() {
		return code
	}
	return ""
}

// Paint wraps s in code and a reset when color is enabled.
func Paint(code, s string) string {
	if Enabled() {
		return code + s + Reset
	}
	return s
}

func detect() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if v, ok := os.LookupEnv("FORCE_COLOR"); ok && v != "0" {
		enableVirtualTerminal()
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	if !xterm.IsTerminal(int(os.Stdout.Fd())) {
		return false
	}
	return enableVirtualTerminal()
}
