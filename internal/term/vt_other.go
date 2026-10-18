//go:build !windows

package term

func enableVirtualTerminal() bool { return true }
