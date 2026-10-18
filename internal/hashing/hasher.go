// Package hashing computes several cryptographic digests in one pass.
package hashing

import (
	"crypto/md5"  //nolint:gosec // MD5 is used for forensic identification (NSRL, VirusTotal), not security
	"crypto/sha1" //nolint:gosec // SHA-1 is used for forensic identification (NSRL, VirusTotal), not security
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"sync"

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

// DefaultAlgorithms are used when none are requested.
var DefaultAlgorithms = []Algorithm{MD5, SHA1, SHA256}

// Supported lists every algorithm the package implements.
var Supported = []Algorithm{MD5, SHA1, SHA256, SHA512, SHA3_256, SHA3_512}

// Result holds hash results.
type Result struct {
	// Algorithms maps algorithm name to lowercase hex digest.
	Algorithms map[string]string `json:"algorithms"`
	FileSize   int64             `json:"file_size"`
	// Order lists the algorithms in the order they were requested.
	Order []string `json:"-"`
}

// ParseAlgorithm validates an algorithm name, accepting common spellings
// such as "SHA-256" and "sha3_256".
func ParseAlgorithm(name string) (Algorithm, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	switch n {
	case "sha-1":
		n = "sha1"
	case "sha-256":
		n = "sha256"
	case "sha-512":
		n = "sha512"
	}
	for _, a := range Supported {
		if string(a) == n {
			return a, nil
		}
	}
	names := make([]string, len(Supported))
	for i, a := range Supported {
		names[i] = string(a)
	}
	return "", fmt.Errorf("unsupported hash algorithm %q (supported: %s)", name, strings.Join(names, ", "))
}

// Compute calculates hashes of an in-memory buffer.
func Compute(data []byte, algorithms []Algorithm) *Result {
	algorithms = normalise(algorithms)
	r := newResult(algorithms, int64(len(data)))
	hs := newHashes(algorithms)
	parallel(hs, data)
	r.fill(algorithms, hs)
	return r
}

// ComputeFile calculates hashes of a file, streaming it once and hashing
// with every algorithm in parallel.
func ComputeFile(path string, algorithms []Algorithm) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return ComputeReader(f, info.Size(), algorithms)
}

// ComputeReader hashes everything read from rd. size is reported as the
// file size; pass -1 to use the number of bytes read.
func ComputeReader(rd io.Reader, size int64, algorithms []Algorithm) (*Result, error) {
	algorithms = normalise(algorithms)
	hs := newHashes(algorithms)

	const chunk = 1 << 20
	bufs := [2][]byte{make([]byte, chunk), make([]byte, chunk)}
	var total int64
	var wg sync.WaitGroup
	cur := 0
	for {
		n, err := io.ReadFull(rd, bufs[cur])
		wg.Wait() // the previous chunk must be hashed before its buffer is reused
		if n > 0 {
			total += int64(n)
			b := bufs[cur][:n]
			wg.Add(1)
			go func() {
				defer wg.Done()
				parallel(hs, b)
			}()
			cur ^= 1
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			wg.Wait()
			return nil, err
		}
	}
	wg.Wait()

	if size < 0 {
		size = total
	}
	r := newResult(algorithms, size)
	r.fill(algorithms, hs)
	return r, nil
}

func normalise(a []Algorithm) []Algorithm {
	if len(a) == 0 {
		return DefaultAlgorithms
	}
	seen := map[Algorithm]bool{}
	out := a[:0:0]
	for _, x := range a {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func newResult(algorithms []Algorithm, size int64) *Result {
	return &Result{Algorithms: make(map[string]string, len(algorithms)), FileSize: size}
}

func (r *Result) fill(algorithms []Algorithm, hs []hash.Hash) {
	for i, a := range algorithms {
		r.Algorithms[string(a)] = fmt.Sprintf("%x", hs[i].Sum(nil))
		r.Order = append(r.Order, string(a))
	}
}

func newHashes(algorithms []Algorithm) []hash.Hash {
	hs := make([]hash.Hash, len(algorithms))
	for i, a := range algorithms {
		hs[i] = newHash(a)
	}
	return hs
}

// parallel feeds b to every hash concurrently.
func parallel(hs []hash.Hash, b []byte) {
	if len(hs) == 1 {
		hs[0].Write(b)
		return
	}
	var wg sync.WaitGroup
	wg.Add(len(hs))
	for _, h := range hs {
		go func(h hash.Hash) {
			defer wg.Done()
			h.Write(b)
		}(h)
	}
	wg.Wait()
}

func newHash(algo Algorithm) hash.Hash {
	switch algo {
	case MD5:
		return md5.New() //nolint:gosec // see import comment
	case SHA1:
		return sha1.New() //nolint:gosec // see import comment
	case SHA256:
		return sha256.New()
	case SHA512:
		return sha512.New()
	case SHA3_256:
		return sha3.New256()
	case SHA3_512:
		return sha3.New512()
	}
	panic("hashing: unsupported algorithm " + string(algo))
}

// Print displays hash results in request order.
func Print(r *Result) {
	fmt.Println()
	fmt.Printf("  Size: %d bytes\n", r.FileSize)
	for _, algo := range r.ordered() {
		fmt.Printf("  %-9s %s\n", algo, r.Algorithms[algo])
	}
	fmt.Println()
}

func (r *Result) ordered() []string {
	if len(r.Order) == len(r.Algorithms) {
		return r.Order
	}
	var out []string
	for _, a := range Supported {
		if _, ok := r.Algorithms[string(a)]; ok {
			out = append(out, string(a))
		}
	}
	return out
}
