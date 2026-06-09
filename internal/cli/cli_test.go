package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRootCommand(t *testing.T) {
	// Test that root command exists
	if rootCmd == nil {
		t.Fatal("rootCmd is nil")
	}

	if rootCmd.Use != "filo" {
		t.Errorf("Expected Use 'filo', got %s", rootCmd.Use)
	}
}

func TestVersionCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	// Version command outputs to stdout, so check that it executed without error
}

func TestAnalyzeCommand(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"analyze", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze command failed: %v", err)
	}
}

func TestHashCommand(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("test data for hashing"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"hash", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("hash command failed: %v", err)
	}

	// Hash command outputs to stdout
}

func TestStringsCommand(t *testing.T) {
	// Create test file with strings
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("Hello World\x00\x00\x00Test String\x00\x00\x00Another test"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"strings", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("strings command failed: %v", err)
	}
}

func TestEntropyCommand(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"entropy", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("entropy command failed: %v", err)
	}
}

func TestHexCommand(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"hex", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("hex command failed: %v", err)
	}
}

func TestScanCommand(t *testing.T) {
	// Create test file with signature
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pdf")
	if err := os.WriteFile(testFile, []byte("%PDF-1.4 test content"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"scan", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan command failed: %v", err)
	}
}

func TestSearchCommand(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("Hello World, this is a test file with some content."), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"search", testFile, "Hello"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("search command failed: %v", err)
	}
}

func TestDDCommand(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("ABCDEFGHIJ"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test with simple arguments
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"dd", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("dd command failed: %v", err)
	}
}

func TestFormatsCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"formats"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("formats command failed: %v", err)
	}
}

func TestFormatsListCommand(t *testing.T) {
	// This test requires the formats directory to exist
	// Skip if not in project root
	if _, err := os.Stat("../../formats"); os.IsNotExist(err) {
		t.Skip("formats directory not found, skipping")
	}

	// Set formats directory flag
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"formats", "list", "--formats-dir", "../../formats"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("formats list command failed: %v", err)
	}
}

func TestMissingArgument(t *testing.T) {
	// Test command with missing required argument
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"analyze"})

	// Should fail with missing argument error
	err := rootCmd.Execute()
	if err == nil {
		t.Error("Expected error for missing argument")
	}
}

func TestNonexistentFile(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"analyze", "/nonexistent/file.bin"})

	// Should fail with file not found error
	err := rootCmd.Execute()
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestPluginsCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"plugins"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("plugins command failed: %v", err)
	}
}

func TestPluginsListCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"plugins", "list"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("plugins list command failed: %v", err)
	}
}
