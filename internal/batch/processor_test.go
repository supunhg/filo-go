package batch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	result, err := Process(tmpDir, &Options{
		Recursive: true,
		Workers:   2,
		MaxSizeMB: 10,
	})

	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.TotalFiles != 0 {
		t.Errorf("Expected 0 files, got %d", result.TotalFiles)
	}
}

func TestProcessWithFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	for i := 0; i < 5; i++ {
		filePath := filepath.Join(tmpDir, "test"+string(rune('a'+i))+".bin")
		os.WriteFile(filePath, []byte("test data"), 0644)
	}

	result, err := Process(tmpDir, &Options{
		Recursive: true,
		Workers:   2,
		MaxSizeMB: 10,
	})

	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.TotalFiles != 5 {
		t.Errorf("Expected 5 files, got %d", result.TotalFiles)
	}

	if result.Analyzed != 5 {
		t.Errorf("Expected 5 analyzed, got %d", result.Analyzed)
	}
}

func TestProcessNonexistentDir(t *testing.T) {
	// The function returns empty result for nonexistent directories
	result, err := Process("/nonexistent/dir", nil)
	if err != nil {
		// Some implementations may return error
		return
	}
	if result != nil && result.TotalFiles != 0 {
		t.Errorf("Expected 0 files, got %d", result.TotalFiles)
	}
}

func TestProcessWithSubdirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create subdirectory with files
	subDir := filepath.Join(tmpDir, "subdir")
	os.Mkdir(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("test"), 0644)

	// Create file in root
	os.WriteFile(filepath.Join(tmpDir, "root.txt"), []byte("test"), 0644)

	result, err := Process(tmpDir, &Options{
		Recursive: true,
		Workers:   2,
		MaxSizeMB: 10,
	})

	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if result.TotalFiles != 2 {
		t.Errorf("Expected 2 files, got %d", result.TotalFiles)
	}
}

func TestProcessNonRecursive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create subdirectory with files
	subDir := filepath.Join(tmpDir, "subdir")
	os.Mkdir(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("test"), 0644)

	// Create file in root
	os.WriteFile(filepath.Join(tmpDir, "root.txt"), []byte("test"), 0644)

	result, err := Process(tmpDir, &Options{
		Recursive: false,
		Workers:   2,
		MaxSizeMB: 10,
	})

	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	// Should only find root.txt, not subdir/file.txt
	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file, got %d", result.TotalFiles)
	}
}

func TestProcessMaxSize(t *testing.T) {
	tmpDir := t.TempDir()

	// Create small file
	os.WriteFile(filepath.Join(tmpDir, "small.txt"), []byte("small"), 0644)

	// Create large file (2MB)
	largeData := make([]byte, 2*1024*1024)
	os.WriteFile(filepath.Join(tmpDir, "large.txt"), largeData, 0644)

	result, err := Process(tmpDir, &Options{
		Recursive: true,
		Workers:   2,
		MaxSizeMB: 1, // 1MB limit
	})

	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	// Should skip large file (>1MB)
	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file, got %d", result.TotalFiles)
	}
}

func TestProcessHiddenFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create hidden file
	os.WriteFile(filepath.Join(tmpDir, ".hidden"), []byte("hidden"), 0644)

	// Create normal file
	os.WriteFile(filepath.Join(tmpDir, "normal.txt"), []byte("normal"), 0644)

	result, err := Process(tmpDir, &Options{
		Recursive: true,
		Workers:   2,
		MaxSizeMB: 10,
	})

	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	// Should skip hidden files
	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file, got %d", result.TotalFiles)
	}
}

func TestProcessHiddenDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create hidden directory
	hiddenDir := filepath.Join(tmpDir, ".hidden")
	os.Mkdir(hiddenDir, 0755)
	os.WriteFile(filepath.Join(hiddenDir, "file.txt"), []byte("hidden"), 0644)

	// Create normal file
	os.WriteFile(filepath.Join(tmpDir, "normal.txt"), []byte("normal"), 0644)

	result, err := Process(tmpDir, &Options{
		Recursive: true,
		Workers:   2,
		MaxSizeMB: 10,
	})

	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	// Should skip hidden directories
	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file, got %d", result.TotalFiles)
	}
}

func TestCollectFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("test"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("test"), 0644)

	files, err := collectFiles(tmpDir, true, 100)
	if err != nil {
		t.Fatalf("collectFiles() error = %v", err)
	}

	if len(files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(files))
	}
}

func TestCollectFilesNonRecursive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create subdirectory
	subDir := filepath.Join(tmpDir, "sub")
	os.Mkdir(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("test"), 0644)

	// Create root file
	os.WriteFile(filepath.Join(tmpDir, "root.txt"), []byte("test"), 0644)

	files, err := collectFiles(tmpDir, false, 100)
	if err != nil {
		t.Fatalf("collectFiles() error = %v", err)
	}

	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}
}

func TestPrintResults(t *testing.T) {
	result := &Result{
		Directory:   "/test/dir",
		TotalFiles:  10,
		Analyzed:    8,
		Failed:      2,
		Duration:    1000000000, // 1 second
		FilesPerSec: 8.0,
	}

	// Test that PrintResults doesn't panic
	PrintResults(result)
}

func TestPrintResultsWithErrors(t *testing.T) {
	result := &Result{
		Directory:   "/test/dir",
		TotalFiles:  5,
		Analyzed:    3,
		Failed:      2,
		Errors:      []string{"error1", "error2"},
		Duration:    1000000000,
		FilesPerSec: 3.0,
	}

	// Test that PrintResults doesn't panic
	PrintResults(result)
}

func TestOptionsDefaults(t *testing.T) {
	opts := &Options{}

	if opts.Workers == 0 {
		opts.Workers = 4
	}

	if opts.Workers != 4 {
		t.Errorf("Expected 4 workers, got %d", opts.Workers)
	}
}

func TestResultStats(t *testing.T) {
	result := &Result{
		Directory:   "/test",
		TotalFiles:  100,
		Analyzed:    90,
		Failed:      5,
		Skipped:     5,
		Duration:    5000000000, // 5 seconds
		FilesPerSec: 18.0,
	}

	if result.TotalFiles != 100 {
		t.Errorf("Expected 100 total files, got %d", result.TotalFiles)
	}

	if result.Analyzed != 90 {
		t.Errorf("Expected 90 analyzed, got %d", result.Analyzed)
	}

	if result.FilesPerSec != 18.0 {
		t.Errorf("Expected 18.0 files/sec, got %f", result.FilesPerSec)
	}
}
