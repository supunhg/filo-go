package cache

import (
	"os"
	"testing"
	"time"
)

func TestCacheNew(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	cache, err := New(dbPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cache.Close()

	if cache == nil {
		t.Error("expected non-nil cache")
	}
}

func TestCacheSetAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	cache, err := New(dbPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cache.Close()

	// Create test file
	testFile := tmpDir + "/test.bin"
	if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Set cache entry
	result := map[string]interface{}{
		"format": "binary",
		"size":   9,
	}
	if err := cache.Set(testFile, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Get cache entry
	entry, err := cache.Get(testFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry == nil {
		t.Fatal("expected non-nil entry")
	}

	if entry.FilePath != testFile {
		t.Errorf("expected path %s, got %s", testFile, entry.FilePath)
	}

	if entry.SHA256 == "" {
		t.Error("expected SHA256 to be set")
	}

	if entry.Result == nil {
		t.Error("expected result to be set")
	}
}

func TestCacheGetNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	cache, err := New(dbPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cache.Close()

	// Get should return error for nonexistent file
	_, err = cache.Get("/nonexistent/file.bin")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestCacheDelete(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	cache, err := New(dbPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cache.Close()

	// Create test file
	testFile := tmpDir + "/test.bin"
	if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Set cache entry
	if err := cache.Set(testFile, "test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Delete cache entry
	if err := cache.Delete(testFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deleted
	entry, err := cache.Get(testFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry != nil {
		t.Error("expected nil entry after deletion")
	}
}

func TestCacheClear(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	cache, err := New(dbPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cache.Close()

	// Create test files and cache them
	for i := 0; i < 5; i++ {
		testFile := tmpDir + "/test" + string(rune('a'+i)) + ".bin"
		if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := cache.Set(testFile, "test"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Clear cache
	if err := cache.Clear(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify cleared
	stats, err := cache.Stats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stats["entries"].(int) != 0 {
		t.Errorf("expected 0 entries, got %d", stats["entries"])
	}
}

func TestCacheStats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	cache, err := New(dbPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cache.Close()

	stats, err := cache.Stats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stats["entries"].(int) != 0 {
		t.Errorf("expected 0 entries, got %d", stats["entries"])
	}
}

func TestFileHash(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.bin"
	if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := FileHash(testFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Same file should give same hash
	hash2, err := FileHash(testFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash != hash2 {
		t.Errorf("expected same hash, got %s and %s", hash, hash2)
	}
}

func TestFileHashNonexistent(t *testing.T) {
	_, err := FileHash("/nonexistent/file.bin")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestIsExpired(t *testing.T) {
	tests := []struct {
		name     string
		entry    *CacheEntry
		maxAge   time.Duration
		expected bool
	}{
		{
			name:     "fresh entry",
			entry:    &CacheEntry{Timestamp: time.Now()},
			maxAge:   time.Hour,
			expected: false,
		},
		{
			name:     "expired entry",
			entry:    &CacheEntry{Timestamp: time.Now().Add(-2 * time.Hour)},
			maxAge:   time.Hour,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsExpired(tt.entry, tt.maxAge)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCacheEntryStructure(t *testing.T) {
	entry := &CacheEntry{
		FilePath:  "/test/file.bin",
		FileSize:  1024,
		SHA256:    "abc123",
		Result:    "test",
		Timestamp: time.Now(),
		Version:   "0.4.0",
	}

	if entry.FilePath != "/test/file.bin" {
		t.Errorf("expected path /test/file.bin, got %s", entry.FilePath)
	}

	if entry.FileSize != 1024 {
		t.Errorf("expected size 1024, got %d", entry.FileSize)
	}

	if entry.Version != "0.4.0" {
		t.Errorf("expected version 0.4.0, got %s", entry.Version)
	}
}
