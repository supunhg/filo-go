package hashing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeDefault(t *testing.T) {
	data := []byte("Hello, World!")
	result := Compute(data, nil)

	if result.FileSize != int64(len(data)) {
		t.Errorf("expected file size %d, got %d", len(data), result.FileSize)
	}

	// Should have MD5, SHA1, SHA256 by default
	if _, ok := result.Algorithms["md5"]; !ok {
		t.Error("expected MD5 hash")
	}
	if _, ok := result.Algorithms["sha1"]; !ok {
		t.Error("expected SHA1 hash")
	}
	if _, ok := result.Algorithms["sha256"]; !ok {
		t.Error("expected SHA256 hash")
	}
}

func TestComputeAllAlgorithms(t *testing.T) {
	data := []byte("Test data")
	algorithms := []Algorithm{MD5, SHA1, SHA256, SHA512, SHA3_256, SHA3_512}
	result := Compute(data, algorithms)

	if len(result.Algorithms) != len(algorithms) {
		t.Errorf("expected %d algorithms, got %d", len(algorithms), len(result.Algorithms))
	}

	// Verify each algorithm produces a different hash
	hashes := make(map[string]bool)
	for algo, hash := range result.Algorithms {
		if hashes[hash] {
			t.Errorf("duplicate hash for algorithm %s", algo)
		}
		hashes[hash] = true
	}
}

func TestComputeEmptyData(t *testing.T) {
	result := Compute([]byte{}, nil)

	if result.FileSize != 0 {
		t.Errorf("expected file size 0, got %d", result.FileSize)
	}

	// Should still produce hashes
	if len(result.Algorithms) == 0 {
		t.Error("expected at least one hash algorithm")
	}
}

func TestComputeConsistency(t *testing.T) {
	data := []byte("Consistent data")

	result1 := Compute(data, []Algorithm{SHA256})
	result2 := Compute(data, []Algorithm{SHA256})

	if result1.Algorithms["sha256"] != result2.Algorithms["sha256"] {
		t.Error("same data should produce same hash")
	}
}

func TestComputeFile(t *testing.T) {
	// Create temporary file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")

	data := []byte("Hello, World!")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	result, err := ComputeFile(tmpFile, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FileSize != int64(len(data)) {
		t.Errorf("expected file size %d, got %d", len(data), result.FileSize)
	}

	// Should have hashes
	if len(result.Algorithms) == 0 {
		t.Error("expected at least one hash algorithm")
	}
}

func TestComputeFileNonexistent(t *testing.T) {
	_, err := ComputeFile("/nonexistent/file.txt", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestComputeFileEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.txt")

	if err := os.WriteFile(tmpFile, []byte{}, 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	result, err := ComputeFile(tmpFile, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FileSize != 0 {
		t.Errorf("expected file size 0, got %d", result.FileSize)
	}
}

func TestComputeFileLarge(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "large.bin")

	// Create 1MB file
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	result, err := ComputeFile(tmpFile, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FileSize != 1024*1024 {
		t.Errorf("expected file size 1048576, got %d", result.FileSize)
	}
}

func TestNewHashDefault(t *testing.T) {
	// Unknown algorithm should return SHA256
	h := newHash("unknown")
	if h == nil {
		t.Error("expected non-nil hash")
	}
}

func TestHashLengths(t *testing.T) {
	data := []byte("test data for hash lengths")

	tests := []struct {
		algo   Algorithm
		length int
	}{
		{MD5, 32},
		{SHA1, 40},
		{SHA256, 64},
		{SHA512, 128},
		{SHA3_256, 64},
		{SHA3_512, 128},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			result := Compute(data, []Algorithm{tt.algo})
			hash := result.Algorithms[string(tt.algo)]

			if len(hash) != tt.length {
				t.Errorf("expected hash length %d, got %d", tt.length, len(hash))
			}
		})
	}
}

func TestResultJSON(t *testing.T) {
	result := Result{
		Algorithms: map[string]string{
			"md5": "abc123",
		},
		FileSize: 1024,
	}

	if result.FileSize != 1024 {
		t.Errorf("expected file size 1024, got %d", result.FileSize)
	}
	if len(result.Algorithms) != 1 {
		t.Errorf("expected 1 algorithm, got %d", len(result.Algorithms))
	}
}

func TestAlgorithmConstants(t *testing.T) {
	if MD5 != "md5" {
		t.Errorf("expected MD5 to be md5, got %s", MD5)
	}
	if SHA1 != "sha1" {
		t.Errorf("expected SHA1 to be sha1, got %s", SHA1)
	}
	if SHA256 != "sha256" {
		t.Errorf("expected SHA256 to be sha256, got %s", SHA256)
	}
	if SHA512 != "sha512" {
		t.Errorf("expected SHA512 to be sha512, got %s", SHA512)
	}
	if SHA3_256 != "sha3-256" {
		t.Errorf("expected SHA3_256 to be sha3-256, got %s", SHA3_256)
	}
	if SHA3_512 != "sha3-512" {
		t.Errorf("expected SHA3_512 to be sha3-512, got %s", SHA3_512)
	}
}
