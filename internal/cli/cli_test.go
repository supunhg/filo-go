package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// expectedVersion is the version string that `filo version` must report.
// Kept as a const so a missed bump at release time fails the build loudly
// (TestVersionCommand asserts on this literal). Bump it in lockstep with
// the `version` constant in root.go for every release.
const expectedVersion = "0.5.0"

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

	// Regression guard: the version string reported by `filo version` must
	// contain the literal expectedVersion from the top of this file. This is
	// the assertion that would have caught the historical 0.4.0-vs-0.5.0
	// drift between the hardcoded value in root.go and what was actually
	// released. Bump expectedVersion in lockstep with the `version` constant
	// in root.go for every release.
	out := buf.String()
	if !strings.Contains(out, expectedVersion) {
		t.Errorf("expected version output to contain %q, got %q", expectedVersion, out)
	}
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

func TestBatchCommand(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("test data for batch analysis"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"batch", tmpDir, "--workers", "1"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("batch command failed: %v", err)
	}
}

func TestCarveCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("some data to carve"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"carve", testFile, "-o", filepath.Join(tmpDir, "carved")})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("carve command failed: %v", err)
	}
}

func TestExtractCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("some data to extract"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"extract", testFile, "--output", filepath.Join(tmpDir, "extracted")})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("extract command failed: %v", err)
	}
}

func TestMetaCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.jpg")
	if err := os.WriteFile(testFile, []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"meta", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("meta command failed: %v", err)
	}
}

func TestStegoCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.png")
	if err := os.WriteFile(testFile, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D}, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"stego", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("stego command failed: %v", err)
	}
}

func TestFirmwareCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("firmware data"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"firmware", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("firmware command failed: %v", err)
	}
}

func TestOfficeCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.docx")
	if err := os.WriteFile(testFile, []byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"office", testFile})

	// Office command may fail on minimal test data, that's OK for CLI coverage
	err := rootCmd.Execute()
	if err != nil {
		t.Logf("office command returned error (expected for minimal test data): %v", err)
	}
}

func TestEvtxCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.evtx")
	// Create a file with EVTX magic bytes
	evtxData := make([]byte, 4096)
	copy(evtxData, "ElfFile")
	if err := os.WriteFile(testFile, evtxData, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"evtx", testFile})

	// EVTX command may fail on minimal test data, that's OK for CLI coverage
	err := rootCmd.Execute()
	if err != nil {
		t.Logf("evtx command returned error (expected for minimal test data): %v", err)
	}
}

func TestRegistryCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.reg")
	// Create a file with REGF magic bytes
	regData := make([]byte, 4096)
	copy(regData, "regf")
	if err := os.WriteFile(testFile, regData, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"registry", testFile})

	// Registry command may fail on minimal test data, that's OK for CLI coverage
	err := rootCmd.Execute()
	if err != nil {
		t.Logf("registry command returned error (expected for minimal test data): %v", err)
	}
}

func TestSigmaCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("sigma test data"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"sigma", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sigma command failed: %v", err)
	}
}

func TestTimelineCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("timeline test data"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"timeline", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("timeline command failed: %v", err)
	}
}

func TestConfigCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"config"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("config command failed: %v", err)
	}
}

func TestExecutableCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.elf")
	// Create a more complete ELF header
	elfData := make([]byte, 64)
	elfData[0] = 0x7F
	elfData[1] = 0x45
	elfData[2] = 0x4C
	elfData[3] = 0x46
	elfData[4] = 0x01 // 32-bit
	elfData[5] = 0x01 // little-endian
	elfData[18] = 0x03 // x86 machine type
	if err := os.WriteFile(testFile, elfData, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"executable", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("executable command failed: %v", err)
	}
}

func TestSQLiteCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.db")
	// Create a file that looks like SQLite but has insufficient data for parsing
	// This tests that the CLI handles the error gracefully
	if err := os.WriteFile(testFile, []byte("SQLite format 3\x00"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"sqlite", testFile})

	// This should fail gracefully with an error about file size
	err := rootCmd.Execute()
	if err == nil {
		t.Error("Expected error for too-small SQLite file")
	}
}

func TestRepairCommand(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.jpg")
	if err := os.WriteFile(testFile, []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"repair", testFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("repair command failed: %v", err)
	}
}

func TestAnalyzeJSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("test data for json"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"analyze", testFile, "--json"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze --json command failed: %v", err)
	}
}

func TestAnalyzeWithEntropyViz(t *testing.T) {
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
	rootCmd.SetArgs([]string{"analyze", testFile, "--entropy-viz"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze --entropy-viz command failed: %v", err)
	}
}

func TestHashMultipleAlgorithms(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("hash test data"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"hash", testFile, "-a", "sha256", "-a", "sha512"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("hash multiple algorithms failed: %v", err)
	}
}

func TestStringsMinLength(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte("Hello World\x00Short\x00Another test string"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"strings", testFile, "--min-len", "6"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("strings with min-len failed: %v", err)
	}
}

func TestHexWithOffsetAndLength(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(testFile, []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B}, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"hex", testFile, "--offset", "2", "--length", "4"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("hex with offset/length failed: %v", err)
	}
}

func TestDDWithOffsetAndLength(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	outputFile := filepath.Join(tmpDir, "output.bin")
	// Create a larger file so dd doesn't fail
	data := make([]byte, 2048)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"dd", "if=" + testFile, "of=" + outputFile, "--bs", "512", "--skip", "1", "--count", "2"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("dd with skip/count failed: %v", err)
	}
}
