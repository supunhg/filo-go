package nsrl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewDatabase(t *testing.T) {
	db := NewDatabase()
	if db == nil {
		t.Fatal("expected non-nil database")
	}
	if db.knownHashes == nil {
		t.Error("expected knownHashes to be initialized")
	}
}

func TestLoadFromList(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "hashes.txt")
	content := "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709\n" + // SHA-1 of empty
		"D41D8CD98F00B204E9800998ECF8427E\n" + // MD5 of empty
		"  E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855  \n" // SHA-256 of empty, with whitespace
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	db := NewDatabase()
	if err := db.LoadFromList(path); err != nil {
		t.Fatalf("LoadFromList: %v", err)
	}

	// Check stats
	stats := db.GetStats()
	if stats.TotalHashes < 3 {
		t.Errorf("expected at least 3 hashes, got %d", stats.TotalHashes)
	}

	// Check that the hashes are present (uppercased)
	if !db.LookupHash("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709") {
		t.Error("expected SHA-1 of empty to be in database")
	}
	if !db.LookupHash("da39a3ee5e6b4b0d3255bfef95601890afd80709") {
		t.Error("expected lowercase SHA-1 of empty to be found (case-insensitive)")
	}
}

func TestLoadFromListNonexistent(t *testing.T) {
	db := NewDatabase()
	if err := db.LoadFromList("/nonexistent/path.txt"); err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadFromCSV(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nsrl.csv")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	writer := csv.NewWriter(f)
	// Header row (skipped by LoadFromCSV) + 2 data rows
	writer.Write([]string{"SHA-1", "MD5", "FileName"})
	writer.Write([]string{"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "D41D8CD98F00B204E9800998ECF8427E", "filename1"})
	writer.Write([]string{"5BA93C9DB0CFF93F52B521D7420E43F6EDA2784F", "098F6BCD4621D373CADE4E832627B4F6", "filename2"})
	writer.Flush()
	f.Close()

	db := NewDatabase()
	if err := db.LoadFromCSV(path); err != nil {
		t.Fatalf("LoadFromCSV: %v", err)
	}

	stats := db.GetStats()
	if stats.TotalFiles < 2 {
		t.Errorf("expected at least 2 files, got %d", stats.TotalFiles)
	}
	if stats.SHA1Count < 2 {
		t.Errorf("expected at least 2 SHA-1 hashes, got %d", stats.SHA1Count)
	}
	if stats.MDF5Count < 2 {
		t.Errorf("expected at least 2 MD5 hashes, got %d", stats.MDF5Count)
	}
}

func TestLoadFromCSVNonexistent(t *testing.T) {
	db := NewDatabase()
	if err := db.LoadFromCSV("/nonexistent/file.csv"); err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadFromCSVSkipsBadRows(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.csv")
	f, _ := os.Create(path)
	w := csv.NewWriter(f)
	w.Write([]string{"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "D41D8CD98F00B204E9800998ECF8427E"})
	w.Write([]string{}) // empty row, should be skipped
	w.Write([]string{"short"})
	w.Flush()
	f.Close()

	db := NewDatabase()
	// Should not panic
	if err := db.LoadFromCSV(path); err != nil {
		t.Fatalf("LoadFromCSV: %v", err)
	}
}

func TestLookupByDataMD5(t *testing.T) {
	db := NewDatabase()
	data := []byte("test data for lookup")
	md5Hash := strings.ToUpper(md5HashBytes(data))
	// Load via a synthetic list
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "hashes.txt")
	if err := os.WriteFile(path, []byte(md5Hash+"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := db.LoadFromList(path); err != nil {
		t.Fatalf("LoadFromList: %v", err)
	}

	r := db.Lookup(data)
	if !r.IsKnown {
		t.Error("expected IsKnown to be true")
	}
	if r.HashType != "MD5" {
		t.Errorf("HashType = %q, want MD5", r.HashType)
	}
}

func TestLookupByDataSHA1(t *testing.T) {
	db := NewDatabase()
	data := []byte("test data for sha1 lookup")
	sha1Hash := strings.ToUpper(sha1HashBytes(data))
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "hashes.txt")
	if err := os.WriteFile(path, []byte(sha1Hash+"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := db.LoadFromList(path); err != nil {
		t.Fatalf("LoadFromList: %v", err)
	}

	r := db.Lookup(data)
	if !r.IsKnown {
		t.Error("expected IsKnown to be true")
	}
	if r.HashType != "SHA-1" {
		t.Errorf("HashType = %q, want SHA-1", r.HashType)
	}
}

func TestLookupByDataSHA256(t *testing.T) {
	db := NewDatabase()
	data := []byte("test data for sha256 lookup")
	sha256Hash := strings.ToUpper(sha256HashBytes(data))
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "hashes.txt")
	if err := os.WriteFile(path, []byte(sha256Hash+"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := db.LoadFromList(path); err != nil {
		t.Fatalf("LoadFromList: %v", err)
	}

	r := db.Lookup(data)
	if !r.IsKnown {
		t.Error("expected IsKnown to be true")
	}
	if r.HashType != "SHA-256" {
		t.Errorf("HashType = %q, want SHA-256", r.HashType)
	}
}

func TestLookupUnknownData(t *testing.T) {
	db := NewDatabase()
	// Empty database
	r := db.Lookup([]byte("anything"))
	if r.IsKnown {
		t.Error("expected IsKnown to be false for empty database")
	}
}

func TestLookupHash(t *testing.T) {
	db := NewDatabase()
	// Empty database — nothing should match
	if db.LookupHash("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709") {
		t.Error("expected LookupHash to return false on empty database")
	}
	// Empty string should also return false
	if db.LookupHash("") {
		t.Error("expected LookupHash of empty string to return false")
	}
}

func TestGetStats(t *testing.T) {
	db := NewDatabase()
	stats := db.GetStats()
	if stats.TotalFiles != 0 {
		t.Errorf("TotalFiles = %d, want 0", stats.TotalFiles)
	}
	if stats.TotalHashes != 0 {
		t.Errorf("TotalHashes = %d, want 0", stats.TotalHashes)
	}
}

func TestPrintStats(t *testing.T) {
	db := NewDatabase()
	// Should not panic with empty database
	PrintStats(db)
}

func TestPrintStatsPopulated(t *testing.T) {
	db := NewDatabase()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "hashes.txt")
	if err := os.WriteFile(path, []byte("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := db.LoadFromList(path); err != nil {
		t.Fatalf("LoadFromList: %v", err)
	}
	// Should not panic
	PrintStats(db)
}

func TestResultStruct(t *testing.T) {
	r := &Result{
		IsKnown:   true,
		HashType:  "SHA-1",
		HashValue: "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
	}
	if !r.IsKnown {
		t.Error("IsKnown not set")
	}
	if r.HashType != "SHA-1" {
		t.Error("HashType not set")
	}
}

func TestStatsStruct(t *testing.T) {
	s := Stats{
		TotalFiles:  100,
		TotalHashes: 200,
		MDF5Count:   100,
		SHA1Count:   100,
	}
	if s.TotalFiles != 100 {
		t.Error("TotalFiles not set")
	}
}

func TestCaseInsensitiveLookup(t *testing.T) {
	db := NewDatabase()
	// Pre-load with uppercase
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "hashes.txt")
	if err := os.WriteFile(path, []byte("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := db.LoadFromList(path); err != nil {
		t.Fatalf("LoadFromList: %v", err)
	}
	// Lookup with lowercase
	if !db.LookupHash("da39a3ee5e6b4b0d3255bfef95601890afd80709") {
		t.Error("expected case-insensitive lookup to succeed")
	}
	// Lookup with mixed case
	if !db.LookupHash("Da39A3eE5E6B4B0D3255BFEF95601890AFd80709") {
		t.Error("expected mixed-case lookup to succeed")
	}
}

// Helper functions to compute hash hex strings
func md5HashBytes(data []byte) string {
	h := md5.Sum(data)
	return toHex(h[:])
}

func sha1HashBytes(data []byte) string {
	h := sha1.Sum(data)
	return toHex(h[:])
}

func sha256HashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return toHex(h[:])
}

func toHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0x0F]
	}
	return string(out)
}
