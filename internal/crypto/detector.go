package crypto

import (
	"bytes"
	"fmt"
	"math"
)

// Result holds crypto detection results.
type Result struct {
	Detected    bool     `json:"detected"`
	Confidence  float64  `json:"confidence"`
	Entropy     float64  `json:"entropy"`
	BlockSize   int      `json:"block_size,omitempty"`
	CipherHints []string `json:"cipher_hints,omitempty"`
	ECBDetected bool     `json:"ecb_detected"`
	Padding     string   `json:"padding,omitempty"`
}

// Analyze performs cryptographic analysis.
func Analyze(data []byte) *Result {
	result := &Result{
		CipherHints: []string{},
	}

	if len(data) < 16 {
		return result
	}

	// Calculate entropy
	entropy := calculateEntropy(data)
	result.Entropy = entropy

	// High entropy indicates encryption
	if entropy > 7.5 {
		result.Detected = true
		result.Confidence = math.Min(entropy/8.0, 0.95)
	}

	// Check block alignment
	blockSizes := []struct {
		size int
		name string
	}{
		{16, "AES"},
		{8, "DES/Blowfish"},
		{32, "AES-256 (key)"},
	}

	for _, bs := range blockSizes {
		if len(data)%bs.size == 0 && len(data) > bs.size*2 {
			result.BlockSize = bs.size
			result.CipherHints = append(result.CipherHints, bs.name)
			if !result.Detected {
				result.Detected = true
				result.Confidence = 0.6
			}
		}
	}

	// Check for ECB mode (repeating blocks)
	if len(data) >= 48 {
		blockSize := result.BlockSize
		if blockSize == 0 {
			blockSize = 16
		}
		if detectECB(data, blockSize) {
			result.ECBDetected = true
			result.CipherHints = append(result.CipherHints, "ECB mode detected")
		}
	}

	// Check for PKCS#7 padding
	if len(data) >= 16 {
		if _, valid := detectPKCS7(data); valid {
			result.Padding = "PKCS#7"
			result.CipherHints = append(result.CipherHints, "PKCS#7 padding")
		}
	}

	// Check for known formats
	if bytes.HasPrefix(data, []byte("Salted__")) {
		result.CipherHints = append(result.CipherHints, "OpenSSL enc format")
		result.Confidence = 0.95
	}

	if bytes.HasPrefix(data, []byte("-----BEGIN PGP")) {
		result.CipherHints = append(result.CipherHints, "PGP/GPG encrypted")
		result.Confidence = 0.95
	}

	return result
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	size := float64(len(data))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / size
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func detectECB(data []byte, blockSize int) bool {
	if len(data) < blockSize*3 {
		return false
	}

	blocks := make(map[string]int)
	for i := 0; i <= len(data)-blockSize; i += blockSize {
		block := string(data[i : i+blockSize])
		blocks[block]++
		if blocks[block] > 1 {
			return true
		}
	}
	return false
}

func detectPKCS7(data []byte) (int, bool) {
	if len(data) == 0 {
		return 0, false
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > 16 || padLen > len(data) {
		return 0, false
	}

	valid := true
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			valid = false
			break
		}
	}

	return padLen, valid
}

// Print displays crypto results.
func Print(r *Result) {
	fmt.Println()
	if r.Detected {
		fmt.Printf("  Encryption Detected: %.0f%% confidence\n", r.Confidence*100)
		fmt.Printf("  Entropy: %.2f bits/byte\n", r.Entropy)
		if r.BlockSize > 0 {
			fmt.Printf("  Block Size: %d bytes\n", r.BlockSize)
		}
		if len(r.CipherHints) > 0 {
			fmt.Println("  Cipher Hints:")
			for _, h := range r.CipherHints {
				fmt.Printf("    • %s\n", h)
			}
		}
		if r.ECBDetected {
			fmt.Println("  ⚠  ECB mode detected (security vulnerability)")
		}
		if r.Padding != "" {
			fmt.Printf("  Padding: %s\n", r.Padding)
		}
	} else {
		fmt.Printf("  No strong encryption detected (entropy: %.2f)\n", r.Entropy)
	}
	fmt.Println()
}
