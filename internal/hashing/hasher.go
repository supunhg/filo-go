package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"

	"golang.org/x/crypto/sha3"
)

// Algorithm represents a hash algorithm.
type Algorithm string

const (
	MD5      Algorithm = "md5"
	SHA1     Algorithm = "sha1"
	SHA256   Algorithm = "sha256"
	SHA512   Algorithm = "sha512"
	SHA3_256 Algorithm = "sha3-256"
	SHA3_512 Algorithm = "sha3-512"
)

// Result holds hash results.
type Result struct {
	Algorithms map[string]string `json:"algorithms"`
	FileSize   int64             `json:"file_size"`
}

// Compute calculates hashes using multiple algorithms.
func Compute(data []byte, algorithms []Algorithm) *Result {
	if len(algorithms) == 0 {
		algorithms = []Algorithm{MD5, SHA1, SHA256}
	}

	result := &Result{
		Algorithms: make(map[string]string),
		FileSize:   int64(len(data)),
	}

	for _, algo := range algorithms {
		h := newHash(algo)
		h.Write(data)
		result.Algorithms[string(algo)] = fmt.Sprintf("%x", h.Sum(nil))
	}

	return result
}

// ComputeFile calculates hashes for a file.
func ComputeFile(path string, algorithms []Algorithm) (*Result, error) {
	if len(algorithms) == 0 {
		algorithms = []Algorithm{MD5, SHA1, SHA256}
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	result := &Result{
		Algorithms: make(map[string]string),
		FileSize:   info.Size(),
	}

	hashes := make(map[Algorithm]hash.Hash)
	for _, algo := range algorithms {
		hashes[algo] = newHash(algo)
	}

	buf := make([]byte, 64*1024) // 64KB buffer
	for {
		n, err := file.Read(buf)
		if n > 0 {
			for _, h := range hashes {
				h.Write(buf[:n])
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	for algo, h := range hashes {
		result.Algorithms[string(algo)] = fmt.Sprintf("%x", h.Sum(nil))
	}

	return result, nil
}

func newHash(algo Algorithm) hash.Hash {
	switch algo {
	case MD5:
		return md5.New()
	case SHA1:
		return sha1.New()
	case SHA256:
		return sha256.New()
	case SHA512:
		return sha512.New()
	case SHA3_256:
		return sha3.New256()
	case SHA3_512:
		return sha3.New512()
	default:
		return sha256.New()
	}
}

// Print displays hash results.
func Print(r *Result) {
	fmt.Println()
	fmt.Println("  Hash Results")
	fmt.Println()
	fmt.Printf("  File Size: %d bytes\n", r.FileSize)
	fmt.Println()

	for algo, hash := range r.Algorithms {
		fmt.Printf("  %-10s %s\n", algo+":", hash)
	}
	fmt.Println()
}
