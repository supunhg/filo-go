package batch

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/supunhg/filo-go/internal/analyzer"
)

// Result holds batch processing results.
type Result struct {
	Directory   string             `json:"directory"`
	TotalFiles  int                `json:"total_files"`
	Analyzed    int                `json:"analyzed"`
	Failed      int                `json:"failed"`
	Skipped     int                `json:"skipped"`
	Results     []*analyzer.Result `json:"results"`
	Errors      []string           `json:"errors"`
	Duration    time.Duration      `json:"duration"`
	FilesPerSec float64            `json:"files_per_sec"`
}

// Options controls batch processing behavior.
type Options struct {
	Recursive  bool
	Workers    int
	MaxSizeMB  int
	FormatsDir string
}

// Process analyzes all files in a directory.
func Process(dir string, opts *Options) (*Result, error) {
	if opts == nil {
		opts = &Options{Recursive: true, Workers: 4, MaxSizeMB: 100}
	}

	result := &Result{
		Directory: dir,
		Results:   []*analyzer.Result{},
		Errors:    []string{},
	}

	start := time.Now()

	// Collect files
	files, err := collectFiles(dir, opts.Recursive, opts.MaxSizeMB)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}
	result.TotalFiles = len(files)

	// Process with goroutines
	var mu sync.Mutex
	var wg sync.WaitGroup
	fileChan := make(chan string, opts.Workers)

	// Start workers
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range fileChan {
				data, err := os.ReadFile(filePath)
				if err != nil {
					mu.Lock()
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filePath, err))
					result.Failed++
					mu.Unlock()
					continue
				}

				analysisResult, err := analyzer.Analyze(data, filePath, &analyzer.Options{
					FormatsDir: opts.FormatsDir,
				})
				if err != nil {
					mu.Lock()
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filePath, err))
					result.Failed++
					mu.Unlock()
					continue
				}

				mu.Lock()
				result.Results = append(result.Results, analysisResult)
				result.Analyzed++
				mu.Unlock()
			}
		}()
	}

	// Feed files to workers
	for _, f := range files {
		fileChan <- f
	}
	close(fileChan)

	wg.Wait()

	result.Duration = time.Since(start)
	if result.Duration.Seconds() > 0 {
		result.FilesPerSec = float64(result.Analyzed) / result.Duration.Seconds()
	}

	return result, nil
}

func collectFiles(dir string, recursive bool, maxSizeMB int) ([]string, error) {
	var files []string
	maxSize := int64(maxSizeMB) * 1024 * 1024

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			if !recursive && path != dir {
				return filepath.SkipDir
			}
			// Skip hidden directories
			if info.Name()[0] == '.' {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden files
		if info.Name()[0] == '.' {
			return nil
		}

		// Skip by size
		if maxSize > 0 && info.Size() > maxSize {
			return nil
		}

		files = append(files, path)
		return nil
	})

	return files, err
}

// PrintResults displays batch results.
func PrintResults(r *Result) {
	fmt.Println()
	fmt.Printf("  Batch Analysis Complete\n")
	fmt.Println()
	fmt.Printf("  Directory: %s\n", r.Directory)
	fmt.Printf("  Total Files: %d\n", r.TotalFiles)
	fmt.Printf("  Analyzed: %d\n", r.Analyzed)
	fmt.Printf("  Failed: %d\n", r.Failed)
	fmt.Printf("  Duration: %v\n", r.Duration)
	fmt.Printf("  Speed: %.1f files/sec\n", r.FilesPerSec)
	fmt.Println()

	if len(r.Results) > 0 {
		fmt.Println("  Results:")
		for _, res := range r.Results {
			fmt.Printf("    %-40s %s (%.1f%%)\n",
				filepath.Base(res.FilePath),
				res.PrimaryFormat,
				res.Confidence*100)
		}
		fmt.Println()
	}

	if len(r.Errors) > 0 {
		fmt.Println("  Errors:")
		for _, e := range r.Errors {
			fmt.Printf("    %s\n", e)
		}
		fmt.Println()
	}
}
