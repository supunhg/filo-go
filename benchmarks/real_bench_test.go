package benchmarks

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/supunhg/filo-go/internal/analyzer"
	"github.com/supunhg/filo-go/internal/carver"
	"github.com/supunhg/filo-go/internal/entropy"
	"github.com/supunhg/filo-go/internal/hashing"
	filostrings "github.com/supunhg/filo-go/internal/strings"
)

// createMixedFile creates a file with embedded signatures
func createMixedFile(t *testing.T) string {
	t.Helper()
	data := make([]byte, 10*1024*1024) // 10MB
	rand.Read(data)

	// Embed PNG signature at offset 1000
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	copy(data[1000:], pngMagic)

	// Embed ZIP signature at offset 5000
	zipMagic := []byte{0x50, 0x4B, 0x03, 0x04}
	copy(data[5000:], zipMagic)

	// Embed ELF signature at offset 8000
	elfMagic := []byte{0x7F, 0x45, 0x4C, 0x46}
	copy(data[8000:], elfMagic)

	tmpFile := filepath.Join(t.TempDir(), "mixed.bin")
	os.WriteFile(tmpFile, data, 0644)
	return tmpFile
}

// BenchmarkFiloAnalyze benchmarks filo-go file analysis
func BenchmarkFiloAnalyze(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				analyzer.Analyze(data, "test.bin", nil)
			}
		})
	}
}

// BenchmarkBinwalkScan benchmarks binwalk signature scan
func BenchmarkBinwalkScan(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			tmpFile := filepath.Join(b.TempDir(), "test.bin")
			os.WriteFile(tmpFile, data, 0644)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cmd := exec.Command("binwalk", tmpFile)
				cmd.Run()
			}
		})
	}
}

// BenchmarkFiloEntropy benchmarks filo-go entropy calculation
func BenchmarkFiloEntropy(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				entropy.Calculate(data)
			}
		})
	}
}

// BenchmarkBinwalkEntropy benchmarks binwalk entropy analysis
func BenchmarkBinwalkEntropy(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			tmpFile := filepath.Join(b.TempDir(), "test.bin")
			os.WriteFile(tmpFile, data, 0644)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cmd := exec.Command("binwalk", "-E", tmpFile)
				cmd.Run()
			}
		})
	}
}

// BenchmarkFiloHash benchmarks filo-go hash computation
func BenchmarkFiloHash(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hashing.Compute(data, []hashing.Algorithm{hashing.SHA256})
			}
		})
	}
}

// BenchmarkBinwalkHash benchmarks binwalk hash (if available)
func BenchmarkBinwalkHash(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			tmpFile := filepath.Join(b.TempDir(), "test.bin")
			os.WriteFile(tmpFile, data, 0644)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cmd := exec.Command("sha256sum", tmpFile)
				cmd.Run()
			}
		})
	}
}

// BenchmarkFiloStrings benchmarks filo-go string extraction
func BenchmarkFiloStrings(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				filostrings.Extract(data, "test.bin", &filostrings.Options{MinLength: 4})
			}
		})
	}
}

// BenchmarkBinwalkStrings benchmarks binwalk string extraction
func BenchmarkBinwalkStrings(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			tmpFile := filepath.Join(b.TempDir(), "test.bin")
			os.WriteFile(tmpFile, data, 0644)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cmd := exec.Command("strings", tmpFile)
				cmd.Run()
			}
		})
	}
}

// BenchmarkFiloCarve benchmarks filo-go file carving
func BenchmarkFiloCarve(b *testing.B) {
	tmpFile := createMixedFile(&testing.T{})

	data, _ := os.ReadFile(tmpFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		carver.Carve(data, tmpFile, &carver.Options{
			MinSize: 100,
			MaxSize: 1024*1024,
		})
	}
}

// BenchmarkBinwalkCarve benchmarks binwalk file carving
func BenchmarkBinwalkCarve(b *testing.B) {
	tmpFile := createMixedFile(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("binwalk", "-e", tmpFile)
		cmd.Run()
	}
}

// BenchmarkFiloScan benchmarks filo-go signature scanning
func BenchmarkFiloScan(b *testing.B) {
	tmpFile := createMixedFile(&testing.T{})

	data, _ := os.ReadFile(tmpFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		carver.ScanSignatures(data)
	}
}

// BenchmarkBinwalkScanFull benchmarks binwalk full scan
func BenchmarkBinwalkScanFull(b *testing.B) {
	tmpFile := createMixedFile(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("binwalk", tmpFile)
		cmd.Run()
	}
}

// RealWorldComparison performs a head-to-head comparison
func TestRealWorldComparison(t *testing.T) {
	fmt.Println("\n=== Real-World Performance Comparison ===")
	fmt.Println("filo-go vs binwalk vs standard tools")
	fmt.Println()

	// Test 1: File Analysis (signature detection)
	t.Run("FileAnalysis", func(t *testing.T) {
		data := make([]byte, 1024*1024) // 1MB
		rand.Read(data)

		// filo-go
		start := time.Now()
		analyzer.Analyze(data, "test.bin", nil)
		filoTime := time.Since(start)

		// binwalk
		tmpFile := filepath.Join(t.TempDir(), "test.bin")
		os.WriteFile(tmpFile, data, 0644)

		start = time.Now()
		cmd := exec.Command("binwalk", tmpFile)
		cmd.Run()
		binwalkTime := time.Since(start)

		speedup := float64(binwalkTime) / float64(filoTime)
		fmt.Printf("File Analysis (1MB):\n")
		fmt.Printf("  filo-go:   %v\n", filoTime)
		fmt.Printf("  binwalk:   %v\n", binwalkTime)
		fmt.Printf("  Speedup:   %.1fx faster\n\n", speedup)
	})

	// Test 2: Entropy Analysis
	t.Run("EntropyAnalysis", func(t *testing.T) {
		data := make([]byte, 1024*1024) // 1MB
		rand.Read(data)

		// filo-go
		start := time.Now()
		entropy.Calculate(data)
		filoTime := time.Since(start)

		// binwalk
		tmpFile := filepath.Join(t.TempDir(), "test.bin")
		os.WriteFile(tmpFile, data, 0644)

		start = time.Now()
		cmd := exec.Command("binwalk", "-E", tmpFile)
		cmd.Run()
		binwalkTime := time.Since(start)

		speedup := float64(binwalkTime) / float64(filoTime)
		fmt.Printf("Entropy Analysis (1MB):\n")
		fmt.Printf("  filo-go:   %v\n", filoTime)
		fmt.Printf("  binwalk:   %v\n", binwalkTime)
		fmt.Printf("  Speedup:   %.1fx faster\n\n", speedup)
	})

	// Test 3: Hash Computation
	t.Run("HashComputation", func(t *testing.T) {
		data := make([]byte, 1024*1024) // 1MB
		rand.Read(data)

		// filo-go
		start := time.Now()
		hashing.Compute(data, []hashing.Algorithm{hashing.SHA256})
		filoTime := time.Since(start)

		// sha256sum
		tmpFile := filepath.Join(t.TempDir(), "test.bin")
		os.WriteFile(tmpFile, data, 0644)

		start = time.Now()
		cmd := exec.Command("sha256sum", tmpFile)
		cmd.Run()
		shaTime := time.Since(start)

		speedup := float64(shaTime) / float64(filoTime)
		fmt.Printf("Hash Computation (1MB):\n")
		fmt.Printf("  filo-go:   %v\n", filoTime)
		fmt.Printf("  sha256sum: %v\n", shaTime)
		fmt.Printf("  Speedup:   %.1fx faster\n\n", speedup)
	})

	// Test 4: String Extraction
	t.Run("StringExtraction", func(t *testing.T) {
		data := make([]byte, 1024*1024) // 1MB
		rand.Read(data)

		// filo-go
		start := time.Now()
		filostrings.Extract(data, "test.bin", &filostrings.Options{MinLength: 4})
		filoTime := time.Since(start)

		// strings
		tmpFile := filepath.Join(t.TempDir(), "test.bin")
		os.WriteFile(tmpFile, data, 0644)

		start = time.Now()
		cmd := exec.Command("strings", tmpFile)
		cmd.Run()
		stringsTime := time.Since(start)

		speedup := float64(stringsTime) / float64(filoTime)
		fmt.Printf("String Extraction (1MB):\n")
		fmt.Printf("  filo-go:   %v\n", filoTime)
		fmt.Printf("  strings:   %v\n", stringsTime)
		fmt.Printf("  Speedup:   %.1fx faster\n\n", speedup)
	})

	// Test 5: File Carving
	t.Run("FileCarving", func(t *testing.T) {
		tmpFile := createMixedFile(t)
		data, _ := os.ReadFile(tmpFile)

		// filo-go
		start := time.Now()
		carver.Carve(data, tmpFile, &carver.Options{
			MinSize: 100,
			MaxSize: 1024 * 1024,
		})
		filoTime := time.Since(start)

		// binwalk
		start = time.Now()
		cmd := exec.Command("binwalk", "-e", tmpFile)
		cmd.Run()
		binwalkTime := time.Since(start)

		speedup := float64(binwalkTime) / float64(filoTime)
		fmt.Printf("File Carving (10MB):\n")
		fmt.Printf("  filo-go:   %v\n", filoTime)
		fmt.Printf("  binwalk:   %v\n", binwalkTime)
		fmt.Printf("  Speedup:   %.1fx faster\n\n", speedup)
	})

	// Test 6: Signature Scanning
	t.Run("SignatureScanning", func(t *testing.T) {
		tmpFile := createMixedFile(t)
		data, _ := os.ReadFile(tmpFile)

		// filo-go
		start := time.Now()
		carver.ScanSignatures(data)
		filoTime := time.Since(start)

		// binwalk
		start = time.Now()
		cmd := exec.Command("binwalk", tmpFile)
		cmd.Run()
		binwalkTime := time.Since(start)

		speedup := float64(binwalkTime) / float64(filoTime)
		fmt.Printf("Signature Scanning (10MB):\n")
		fmt.Printf("  filo-go:   %v\n", filoTime)
		fmt.Printf("  binwalk:   %v\n", binwalkTime)
		fmt.Printf("  Speedup:   %.1fx faster\n\n", speedup)
	})

	fmt.Println("=== Comparison Complete ===")
}
