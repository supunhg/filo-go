package crypto

import (
	"testing"
)

func TestAnalyzeEmptyData(t *testing.T) {
	result := Analyze([]byte{})
	if result.Detected {
		t.Error("expected no detection for empty data")
	}
	if result.Entropy != 0 {
		t.Errorf("expected 0 entropy, got %f", result.Entropy)
	}
}

func TestAnalyzeSmallData(t *testing.T) {
	result := Analyze([]byte{0x01, 0x02, 0x03})
	if result.Detected {
		t.Error("expected no detection for small data")
	}
}

func TestAnalyzeTextData(t *testing.T) {
	// Low entropy, printable text
	data := []byte("Hello, World! This is a test message. ")
	result := Analyze(data)

	if result.Detected {
		t.Error("expected no detection for text data")
	}
	if len(result.CipherHints) > 0 {
		t.Errorf("expected no cipher hints for text, got %v", result.CipherHints)
	}
}

func TestAnalyzeHighEntropyData(t *testing.T) {
	// High entropy data (looks like encrypted)
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i * 37 % 256) // Pseudo-random pattern
	}
	result := Analyze(data)

	if !result.Detected {
		t.Error("expected detection for high entropy data")
	}
	if result.Entropy < 5.0 {
		t.Errorf("expected high entropy, got %f", result.Entropy)
	}
}

func TestAnalyzeOpenSSLFormat(t *testing.T) {
	// OpenSSL "Salted__" format
	data := append([]byte("Salted__"), make([]byte, 64)...)
	result := Analyze(data)

	if !result.Detected {
		t.Error("expected detection for OpenSSL format")
	}

	foundOpenSSL := false
	for _, h := range result.CipherHints {
		if h == "OpenSSL enc format" {
			foundOpenSSL = true
			break
		}
	}
	if !foundOpenSSL {
		t.Error("expected OpenSSL enc format hint")
	}
}

func TestAnalyzePGPFormat(t *testing.T) {
	// PGP format (needs to be long enough and have high entropy)
	data := make([]byte, 100)
	copy(data, "-----BEGIN PGP")
	// Fill rest with high entropy data
	for i := 14; i < 100; i++ {
		data[i] = byte(i * 37 % 256)
	}
	result := Analyze(data)

	foundPGP := false
	for _, h := range result.CipherHints {
		if h == "PGP/GPG encrypted" {
			foundPGP = true
			break
		}
	}
	if !foundPGP {
		t.Error("expected PGP/GPG hint")
	}
}

func TestAnalyzeBlockAlignment(t *testing.T) {
	// Data aligned to 16-byte blocks (AES)
	data := make([]byte, 128) // 8 * 16 bytes
	for i := range data {
		data[i] = byte(i)
	}
	result := Analyze(data)

	foundAES := false
	for _, h := range result.CipherHints {
		if h == "AES" {
			foundAES = true
			break
		}
	}
	if !foundAES {
		t.Error("expected AES hint for 16-byte aligned data")
	}
}

func TestAnalyzeDESAlignment(t *testing.T) {
	// Data aligned to 8-byte blocks (DES)
	data := make([]byte, 64) // 8 * 8 bytes
	for i := range data {
		data[i] = byte(i)
	}
	result := Analyze(data)

	foundDES := false
	for _, h := range result.CipherHints {
		if h == "DES/Blowfish" {
			foundDES = true
			break
		}
	}
	if !foundDES {
		t.Error("expected DES/Blowfish hint for 8-byte aligned data")
	}
}

func TestDetectECB(t *testing.T) {
	// Create data with repeating blocks (ECB mode)
	block := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	data := make([]byte, 0)
	for i := 0; i < 10; i++ {
		data = append(data, block...)
	}

	result := Analyze(data)

	if !result.ECBDetected {
		t.Error("expected ECB detection for repeating blocks")
	}
}

func TestDetectPKCS7(t *testing.T) {
	// Data with valid PKCS#7 padding (must be >= 16 bytes)
	data := make([]byte, 32)
	for i := 0; i < 16; i++ {
		data[i] = byte(i)
	}
	// Add PKCS#7 padding (16 bytes of 0x10)
	for i := 16; i < 32; i++ {
		data[i] = 0x10
	}

	result := Analyze(data)

	if result.Padding != "PKCS#7" {
		t.Errorf("expected PKCS#7 padding, got %s", result.Padding)
	}
}

func TestEntropyCalculation(t *testing.T) {
	// All zeros = 0 entropy
	data := make([]byte, 100)
	result := Analyze(data)
	if result.Entropy != 0 {
		t.Errorf("expected 0 entropy for all zeros, got %f", result.Entropy)
	}
}

func TestCipherHintsEmpty(t *testing.T) {
	// Text data should have no cipher hints
	data := []byte("This is just plain text with no encryption.")
	result := Analyze(data)
	if len(result.CipherHints) != 0 {
		t.Errorf("expected no cipher hints for text, got %v", result.CipherHints)
	}
}

func TestConfidenceRange(t *testing.T) {
	// High entropy data
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i * 37 % 256)
	}
	result := Analyze(data)

	if result.Confidence < 0 || result.Confidence > 1 {
		t.Errorf("confidence out of range: %f", result.Confidence)
	}
}
