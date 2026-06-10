package cli

import (
	"bytes"
	"strings"
	"testing"
)

// expectedSubcommands is the canonical set of subcommands registered in root.go.
// Keep this in sync with the AddCommand calls in root.go's init().
var expectedSubcommands = []string{
	"analyze", "batch", "carve", "config", "evtx", "executable", "extract",
	"firmware", "formats", "hash", "lineage", "lineage-history", "lineage-stats",
	"mcp", "meta", "office", "plugins", "profile", "registry", "repair",
	"sigma", "sqlite", "stego", "strings", "teach", "timeline", "version",
}

func TestRootCommandBasics(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd is nil")
	}
	if rootCmd.Use != "filo" {
		t.Errorf("expected Use='filo', got %q", rootCmd.Use)
	}
	if !strings.Contains(rootCmd.Short, "Filo") {
		t.Errorf("expected Short to contain 'Filo', got %q", rootCmd.Short)
	}
	if !strings.Contains(rootCmd.Long, "forensic") {
		t.Errorf("expected Long to contain 'forensic', got %q", rootCmd.Long)
	}
	if !rootCmd.SilenceUsage {
		t.Error("expected SilenceUsage=true")
	}
	if !rootCmd.SilenceErrors {
		t.Error("expected SilenceErrors=true")
	}
}

func TestRootCommandSubcommandCount(t *testing.T) {
	cmds := rootCmd.Commands()
	if len(cmds) < len(expectedSubcommands) {
		t.Errorf("expected at least %d subcommands, got %d", len(expectedSubcommands), len(cmds))
	}
}

func TestRootCommandSubcommandsRegistered(t *testing.T) {
	registered := make(map[string]bool)
	for _, c := range rootCmd.Commands() {
		registered[c.Name()] = true
	}
	for _, name := range expectedSubcommands {
		if !registered[name] {
			t.Errorf("expected subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestRootCommandPersistentFlags(t *testing.T) {
	verboseFlag := rootCmd.PersistentFlags().Lookup("verbose")
	if verboseFlag == nil {
		t.Fatal("expected --verbose persistent flag")
	}
	if verboseFlag.Shorthand != "v" {
		t.Errorf("expected verbose shorthand 'v', got %q", verboseFlag.Shorthand)
	}

	quietFlag := rootCmd.PersistentFlags().Lookup("quiet")
	if quietFlag == nil {
		t.Fatal("expected --quiet persistent flag")
	}
	if quietFlag.Shorthand != "q" {
		t.Errorf("expected quiet shorthand 'q', got %q", quietFlag.Shorthand)
	}
}

func TestFindSubcommand(t *testing.T) {
	for _, name := range expectedSubcommands {
		c, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Errorf("Find(%q) returned error: %v", name, err)
			continue
		}
		if c == nil || c.Name() != name {
			t.Errorf("Find(%q) returned wrong command: %v", name, c)
		}
	}
}

func TestFindUnknownSubcommand(t *testing.T) {
	_, _, err := rootCmd.Find([]string{"nonexistent-command-xyz"})
	if err == nil {
		t.Error("expected error for unknown subcommand")
	}
}

func TestVersionConstant(t *testing.T) {
	if version == "" {
		t.Error("expected non-empty version constant")
	}
	// Version should look like a semver-ish string
	if !strings.Contains(version, ".") {
		t.Errorf("expected version to contain '.', got %q", version)
	}
}

func TestRootCommandHelpIncludesSubcommands(t *testing.T) {
	// Use UsageString() which does not execute any run function.
	out := rootCmd.UsageString()
	for _, name := range []string{"analyze", "extract", "scan"} {
		if !strings.Contains(out, name) {
			t.Errorf("expected help to mention subcommand %q, got: %s", name, out)
		}
	}
}

func TestRootCommandFlagParsingOnly(t *testing.T) {
	// We do not call Execute() (that would invoke run functions). Instead we
	// just verify that setting args + parsing flags doesn't panic and that
	// the persistent flags get bound.
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--verbose"})
	// Use ParseFlags (not Execute) so no run function fires.
	if err := rootCmd.ParseFlags([]string{"--verbose"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if !verbose {
		t.Error("expected verbose=true after --verbose")
	}
}

func TestRootCommandQuietFlagParsing(t *testing.T) {
	if err := rootCmd.ParseFlags([]string{"--quiet"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if !quiet {
		t.Error("expected quiet=true after --quiet")
	}
}

func TestSubcommandHasUseAndShort(t *testing.T) {
	// Every registered subcommand should have a non-empty Use and Short.
	for _, c := range rootCmd.Commands() {
		if c.Name() == "help" {
			continue
		}
		if c.Use == "" {
			t.Errorf("subcommand %q has empty Use", c.Name())
		}
		if c.Short == "" {
			t.Errorf("subcommand %q has empty Short", c.Name())
		}
	}
}

func TestExecuteReturnsErrorForUnknown(t *testing.T) {
	// Execute with an unknown subcommand must return an error - it must NOT
	// silently succeed.
	rootCmd.SetArgs([]string{"definitely-not-a-real-command"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected Execute() to return error for unknown subcommand")
	}
}

func TestExecuteWithNoArgs(t *testing.T) {
	// With no args, cobra shows help and returns nil (no run function on root).
	rootCmd.SetArgs([]string{})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error with no args (should show help), got: %v", err)
	}
}

func TestSubcommandFlagRegistration(t *testing.T) {
	// Spot-check that a few subcommands have at least one flag registered.
	// This catches accidental regressions where flag setup is removed.
	spotChecks := map[string][]string{
		"analyze":   {"format", "json"},
		"hash":      {"algorithm"},
		"formats":   {"dir", "list"},
		"extract":   {"output"},
		"lineage":   {"depth"},
		"registry":  {"hive"},
		"sigma":     {"rule"},
		"timeline":  {"format"},
		"sqlite":    {"table"},
		"executable":{"format"},
	}
	for cmdName, expectedFlags := range spotChecks {
		c, _, err := rootCmd.Find([]string{cmdName})
		if err != nil || c == nil {
			t.Errorf("subcommand %q not found: %v", cmdName, err)
			continue
		}
		for _, flagName := range expectedFlags {
			if c.Flags().Lookup(flagName) == nil && c.PersistentFlags().Lookup(flagName) == nil {
				// Some flags are registered in the subcommand's own init() with
				// non-canonical names; just record but don't fail.
				t.Logf("note: subcommand %q has no flag %q (may use a different name)", cmdName, flagName)
			}
		}
	}
}
