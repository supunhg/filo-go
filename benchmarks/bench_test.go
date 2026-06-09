package benchmarks

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"os"
	"testing"

	"github.com/supunhg/filo-go/internal/entropy"
	hashing "github.com/supunhg/filo-go/internal/hashing"
	"github.com/supunhg/filo-go/internal/strings"
)

// Generate test data of specified size
func generateTestData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// Benchmark entropy calculation
func BenchmarkEntropyCalculate(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB

	for _, size := range sizes {
		data := generateTestData(size)
		b.Run(formatSize(size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				entropy.Calculate(data)
			}
		})
	}
}

// Benchmark entropy chunks
func BenchmarkEntropyChunks(b *testing.B) {
	data := generateTestData(102400) // 100KB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entropy.Chunks(data, 256)
	}
}

// Benchmark hashing (MD5)
func BenchmarkHashingMD5(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB

	for _, size := range sizes {
		data := generateTestData(size)
		b.Run(formatSize(size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				hashing.Compute(data, []hashing.Algorithm{hashing.MD5})
			}
		})
	}
}

// Benchmark hashing (SHA256)
func BenchmarkHashingSHA256(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB

	for _, size := range sizes {
		data := generateTestData(size)
		b.Run(formatSize(size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				hashing.Compute(data, []hashing.Algorithm{hashing.SHA256})
			}
		})
	}
}

// Benchmark string extraction
func BenchmarkStringExtraction(b *testing.B) {
	sizes := []int{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB

	for _, size := range sizes {
		data := generateTestData(size)
		opts := &strings.Options{MinLength: 4, Type: "all"}
		b.Run(formatSize(size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				strings.Extract(data, "test.bin", opts)
			}
		})
	}
}

// Benchmark gzip decompression
func BenchmarkGzipDecompress(b *testing.B) {
	// Create compressed test data
	original := generateTestData(102400) // 100KB
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(original)
	w.Close()
	compressed := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, _ := gzip.NewReader(bytes.NewReader(compressed))
		buf := make([]byte, 0, len(original))
		buf = buf[:0]
		for {
			chunk := make([]byte, 1024)
			n, err := r.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
			}
			if err != nil {
				break
			}
		}
		r.Close()
	}
}

// Benchmark file reading
func BenchmarkFileRead(b *testing.B) {
	// Create temp file
	tmpFile, _ := os.CreateTemp("", "bench-*")
	defer os.Remove(tmpFile.Name())

	data := generateTestData(102400) // 100KB
	tmpFile.Write(data)
	tmpFile.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		os.ReadFile(tmpFile.Name())
	}
}

func formatSize(bytes int) string {
	const (
		KB = 1024
		MB = 1024 * KB
	)

	switch {
	case bytes >= MB:
		return "1MB"
	case bytes >= KB:
		kb := bytes / KB
		if kb == 1 {
			return "1KB"
		} else if kb == 10 {
			return "10KB"
		} else if kb == 100 {
			return "100KB"
		}
		return "1KB"
	default:
		return "1B"
	}
}
