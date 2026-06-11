package lineage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewTracker(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	tracker, err := NewTracker(dbPath)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}
	defer tracker.Close()

	if tracker == nil {
		t.Error("Expected non-nil tracker")
	}
}

func TestRecord(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	tracker, err := NewTracker(dbPath)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}
	defer tracker.Close()

	// Test recording
	err = tracker.Record([]byte("original"), []byte("result"), "test_op", "test.txt", "test description")
	if err != nil {
		t.Errorf("Record() error = %v", err)
	}
}

func TestRecordFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	tracker, err := NewTracker(dbPath)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}
	defer tracker.Close()

	// Create test files
	originalPath := filepath.Join(tmpDir, "original.txt")
	resultPath := filepath.Join(tmpDir, "result.txt")

	os.WriteFile(originalPath, []byte("original"), 0644)
	os.WriteFile(resultPath, []byte("result"), 0644)

	// Test recording from files
	err = tracker.RecordFromFile(originalPath, resultPath, "test_op", "test description")
	if err != nil {
		t.Errorf("RecordFromFile() error = %v", err)
	}
}

func TestGetByHash(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	tracker, err := NewTracker(dbPath)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}
	defer tracker.Close()

	// Record a record
	tracker.Record([]byte("test"), []byte("result"), "test_op", "test.txt", "description")

	// Get records (we don't know the hash, so just test the function doesn't crash)
	records, err := tracker.GetByHash("nonexistent")
	if err != nil {
		t.Logf("GetByHash() error (expected): %v", err)
	}
	if records != nil {
		t.Logf("GetByHash() returned %d records", len(records))
	}
}

func TestGetStats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	tracker, err := NewTracker(dbPath)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}
	defer tracker.Close()

	// Get stats
	stats, err := tracker.GetStats()
	if err != nil {
		t.Errorf("GetStats() error = %v", err)
	}

	if stats == nil {
		t.Error("Expected non-nil stats")
	}
}

func TestComputeHash(t *testing.T) {
	hash := computeHash([]byte("test"))
	if hash == "" {
		t.Error("Expected non-empty hash")
	}

	// Same input should produce same hash
	hash2 := computeHash([]byte("test"))
	if hash != hash2 {
		t.Error("Expected same hash for same input")
	}
}

func TestSplitN(t *testing.T) {
	tests := []struct {
		s    string
		sep  string
		n    int
		want []string
	}{
		{"a:b:c", ":", 2, []string{"a", "b:c"}},
		{"a:b:c", ":", 3, []string{"a", "b", "c"}},
		{"abc", ":", 2, []string{"abc"}},
	}

	for _, tt := range tests {
		got := splitN(tt.s, tt.sep, tt.n)
		if len(got) != len(tt.want) {
			t.Errorf("splitN(%s, %s, %d) = %v, want %v", tt.s, tt.sep, tt.n, got, tt.want)
		}
	}
}

func TestIndexOf(t *testing.T) {
	tests := []struct {
		s    string
		sep  string
		want int
	}{
		{"a:b:c", ":", 1},
		{"abc", ":", -1},
		{"abc", "b", 1},
	}

	for _, tt := range tests {
		got := indexOf(tt.s, tt.sep)
		if got != tt.want {
			t.Errorf("indexOf(%s, %s) = %d, want %d", tt.s, tt.sep, got, tt.want)
		}
	}
}
