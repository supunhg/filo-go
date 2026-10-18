package crypto

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"strings"
	"testing"
)

func randomBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func TestEmptyAndSmallInputs(t *testing.T) {
	for _, d := range [][]byte{nil, []byte("short")} {
		r := Analyze(d)
		if r.Detected || r.Verdict != VerdictTooSmall {
			t.Errorf("Analyze(%q) = %+v, want undetected too-small", d, r)
		}
	}
}

func TestTextIsStructured(t *testing.T) {
	text := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 200))
	r := Analyze(text)
	if r.Detected || r.Verdict != VerdictStructured {
		t.Errorf("text: %+v", r)
	}
}

func TestRandomDataIsRandom(t *testing.T) {
	r := Analyze(randomBytes(64<<10, 1))
	if !r.Detected || r.Verdict != VerdictRandom {
		t.Fatalf("random: %+v", r)
	}
	if r.Container != "" || r.ECBSuspected {
		t.Errorf("random data must not claim a container or ECB: %+v", r)
	}
}

func TestBlockAlignedSizeIsNotEvidence(t *testing.T) {
	// Regression: any file whose length was a multiple of 16 used to be
	// reported as "AES". A structured file of aligned length is not encrypted.
	d := bytes.Repeat([]byte{0, 1, 2, 3, 'A', 'B', 'C', 'D'}, 512) // 4096 bytes
	r := Analyze(d)
	if r.Detected || r.Container != "" {
		t.Errorf("aligned structured data reported as encrypted: %+v", r)
	}
}

func TestCompressedDataIsNotRandom(t *testing.T) {
	// English-like text compressed with deflate keeps a skewed histogram.
	var src bytes.Buffer
	words := strings.Fields("alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu")
	rng := rand.New(rand.NewSource(3))
	for src.Len() < 1<<20 {
		src.WriteString(words[rng.Intn(len(words))])
		src.WriteByte(' ')
	}
	var out bytes.Buffer
	w, _ := flate.NewWriter(&out, flate.BestCompression)
	w.Write(src.Bytes())
	w.Close()
	r := Analyze(out.Bytes())
	if r.Verdict == VerdictRandom {
		t.Errorf("deflate output classified as random: entropy %.3f chi %.1f", r.Entropy, r.ChiSquare)
	}
}

func TestECBDetection(t *testing.T) {
	block, _ := aes.NewCipher(bytes.Repeat([]byte{7}, 16))
	// Plaintext with repeating 16-byte blocks mixed with random blocks.
	plain := randomBytes(32<<10, 9)
	rep := randomBytes(16, 10)
	for i := 0; i < len(plain); i += 16 * 8 {
		copy(plain[i:], rep)
	}
	enc := make([]byte, len(plain))
	for i := 0; i < len(plain); i += 16 {
		block.Encrypt(enc[i:i+16], plain[i:i+16])
	}
	r := Analyze(enc)
	if !r.ECBSuspected || r.RepeatedBlocks == 0 {
		t.Errorf("ECB ciphertext not flagged: %+v", r)
	}

	// The same plaintext in CTR mode has no repeated blocks.
	ctr := make([]byte, len(plain))
	cipher.NewCTR(block, make([]byte, 16)).XORKeyStream(ctr, plain)
	if r := Analyze(ctr); r.ECBSuspected {
		t.Errorf("CTR ciphertext flagged as ECB: %+v", r)
	}
}

func TestContainers(t *testing.T) {
	cases := map[string][]byte{
		"OpenSSL enc":        append([]byte("Salted__12345678"), randomBytes(64, 2)...),
		"OpenPGP message":    []byte("-----BEGIN PGP MESSAGE-----\n\nhQEMA..."),
		"age encrypted file": []byte("age-encryption.org/v1\n-> X25519 abc\n"),
		"LUKS":               append([]byte("LUKS\xba\xbe\x00\x02"), make([]byte, 100)...),
		"BitLocker":          append([]byte("\xeb\x58\x90-FVE-FS-"), make([]byte, 100)...),
	}
	for want, d := range cases {
		r := Analyze(d)
		if !r.Detected || !strings.Contains(r.Container, want) {
			t.Errorf("%s: got %+v", want, r)
		}
	}
}

func TestChiSquareOfUniformData(t *testing.T) {
	// A perfectly uniform histogram has a statistic of exactly zero.
	d := make([]byte, 256*16)
	for i := range d {
		d[i] = byte(i)
	}
	if got := chiSquare(d); got != 0 {
		t.Errorf("chiSquare(uniform) = %v, want 0", got)
	}
}
