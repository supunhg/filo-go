//go:build windows

package term

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal turns on ANSI escape processing for the Windows
// console. It reports false when the console does not support it.
func enableVirtualTerminal() bool {
	h := windows.Handle(os.Stdout.Fd())
	var m uint32
	if err := windows.GetConsoleMode(h, &m); err != nil {
		return false
	}
	if m&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(h, m|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
