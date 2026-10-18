// Package crypto looks for evidence that data is encrypted.
//
// Ciphertext from a modern cipher is indistinguishable from random bytes, so
// no tool can name the algorithm from the bytes alone. This package reports
// what can honestly be measured:
//
//   - known encryption containers identified by their headers (OpenSSL enc,
//     OpenPGP, age, LUKS, BitLocker, ...);
//   - whether the byte distribution is consistent with random data, using
//     Shannon entropy together with a chi-square goodness-of-fit test, which
//     separates encrypted or random data from compressed data far better than
//     entropy alone;
//   - repeated aligned 16-byte blocks inside otherwise high-entropy data, a
//     classic sign of ECB-mode encryption.
package crypto

import (
	"bytes"
	"fmt"
	"math"

	"github.com/supunhg/filo-go/internal/entropy"
)

// Verdict summarises how random the data looks.
type Verdict string

const (
	// VerdictTooSmall means there is not enough data for a meaningful test.
	VerdictTooSmall Verdict = "too-small"
	// VerdictStructured means the byte distribution is far from uniform.
	VerdictStructured Verdict = "structured"
	// VerdictCompressed means high entropy but a non-uniform distribution,
	// typical of deflate, LZMA, media codecs and other compressed data.
	VerdictCompressed Verdict = "compressed"
	// VerdictRandom means the data is statistically indistinguishable from
	// uniform random bytes: encrypted, random, or very well compressed.
	VerdictRandom Verdict = "random"
)

// minSample is the smallest input on which the randomness test is run. The
// chi-square test needs several observations per byte value to be reliable.
const minSample = 1024

// Result holds encryption analysis results.
type Result struct {
	// Detected is true when a known encryption container was identified or
	// the data is statistically random.
	Detected bool `json:"detected"`
	// Confidence is a 0..1 score for Detected.
	Confidence float64 `json:"confidence"`
	// Entropy is the Shannon entropy in bits per byte.
	Entropy float64 `json:"entropy"`
	// ChiSquare is the chi-square statistic of the byte histogram against a
	// uniform distribution (255 degrees of freedom; random data averages 255).
	ChiSquare float64 `json:"chi_square"`
	// Verdict classifies the byte distribution.
	Verdict Verdict `json:"verdict"`
	// Container names an identified encryption format, if any.
	Container string `json:"container,omitempty"`
	// Details holds format-specific facts parsed from the container header.
	Details []string `json:"details,omitempty"`
	// RepeatedBlocks counts aligned 16-byte blocks that occur more than once.
	RepeatedBlocks int `json:"repeated_blocks,omitempty"`
	// ECBSuspected is set when repeated blocks appear in high-entropy data.
	ECBSuspected bool `json:"ecb_suspected,omitempty"`
}

// Analyze inspects data for encryption.
func Analyze(data []byte) *Result {
	r := &Result{Verdict: VerdictTooSmall}
	if len(data) == 0 {
		return r
	}
	r.Entropy = entropy.Calculate(data)

	if name, details, ok := identifyContainer(data); ok {
		r.Detected = true
		r.Confidence = 0.99
		r.Container = name
		r.Details = details
	}

	if len(data) < minSample {
		return r
	}
	r.ChiSquare = chiSquare(data)
	r.Verdict = classify(r.Entropy, r.ChiSquare)

	if r.Verdict == VerdictRandom && r.Container == "" {
		r.Detected = true
		r.Confidence = randomConfidence(r.ChiSquare)
	}

	if r.Entropy > 7.0 {
		r.RepeatedBlocks = repeatedBlocks(data, 16)
		// Random data essentially never repeats a 16-byte block, and only
		// diverse blocks count, so zero padding and fill patterns are ignored.
		r.ECBSuspected = r.RepeatedBlocks > 0
	}
	return r
}

// chiSquare returns the chi-square statistic of the byte histogram.
func chiSquare(data []byte) float64 {
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	expected := float64(len(data)) / 256
	var chi float64
	for _, f := range freq {
		d := float64(f) - expected
		chi += d * d / expected
	}
	return chi
}

// classify maps entropy and chi-square to a verdict. With 255 degrees of
// freedom the chi-square statistic of uniform data has mean 255 and standard
// deviation about 22.6; anything above ~350 (p < 0.0001) is not uniform.
func classify(ent, chi float64) Verdict {
	switch {
	case ent < 7.0:
		return VerdictStructured
	case chi <= 350:
		return VerdictRandom
	default:
		return VerdictCompressed
	}
}

func randomConfidence(chi float64) float64 {
	// Values close to the expected mean are the most convincing; both very
	// small and large statistics are less likely under true randomness.
	z := math.Abs(chi-255) / 22.6
	return math.Max(0.5, math.Min(0.95, 0.95-0.1*math.Max(0, z-1)))
}

func repeatedBlocks(data []byte, size int) int {
	seen := make(map[string]struct{}, len(data)/size)
	repeats := 0
	for i := 0; i+size <= len(data); i += size {
		blk := data[i : i+size]
		if distinct(blk) < 12 {
			continue
		}
		k := string(blk)
		if _, ok := seen[k]; ok {
			repeats++
			continue
		}
		seen[k] = struct{}{}
	}
	return repeats
}

func distinct(b []byte) int {
	var seen [256]bool
	n := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
}

// identifyContainer recognises encryption formats by their headers.
func identifyContainer(d []byte) (string, []string, bool) {
	switch {
	case bytes.HasPrefix(d, []byte("Salted__")):
		return "OpenSSL enc (salted)", []string{fmt.Sprintf("salt %x", d[8:min(16, len(d))])}, true
	case bytes.HasPrefix(d, []byte("-----BEGIN PGP MESSAGE-----")):
		return "OpenPGP message (ASCII armored)", nil, true
	case bytes.HasPrefix(d, []byte("age-encryption.org/v1\n")):
		return "age encrypted file", nil, true
	case bytes.HasPrefix(d, []byte("-----BEGIN AGE ENCRYPTED FILE-----")):
		return "age encrypted file (ASCII armored)", nil, true
	case bytes.HasPrefix(d, []byte("LUKS\xba\xbe")) && len(d) >= 8:
		v := int(d[6])<<8 | int(d[7])
		details := []string{fmt.Sprintf("version %d", v)}
		if v == 1 && len(d) >= 72 {
			details = append(details, "cipher "+cstr(d[8:40])+"-"+cstr(d[40:72]))
		}
		return "LUKS encrypted volume", details, true
	case len(d) >= 11 && string(d[3:11]) == "-FVE-FS-":
		return "BitLocker encrypted volume", nil, true
	case bytes.HasPrefix(d, []byte("\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5")) || bytes.HasPrefix(d, []byte("\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5")):
		return "KeePass database", nil, true
	case bytes.HasPrefix(d, []byte("AES\x01\x00")) || bytes.HasPrefix(d, []byte("AES\x02\x00")):
		return "AES Crypt file", []string{fmt.Sprintf("format version %d", d[3])}, true
	case bytes.HasPrefix(d, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")):
		return "PKCS#8 encrypted private key", nil, true
	case bytes.HasPrefix(d, []byte("openssh-key-v1\x00")) && !bytes.Contains(d[:min(64, len(d))], []byte("none")):
		return "OpenSSH private key (passphrase protected)", nil, true
	case isPGPBinary(d):
		return "OpenPGP message (binary)", nil, true
	}
	return "", nil, false
}

// isPGPBinary recognises a binary OpenPGP public-key- or symmetric-key-
// encrypted session key packet followed by an encrypted data packet.
func isPGPBinary(d []byte) bool {
	if len(d) < 4 || d[0]&0x80 == 0 {
		return false
	}
	var tag byte
	if d[0]&0x40 != 0 {
		tag = d[0] & 0x3F
	} else {
		tag = (d[0] >> 2) & 0x0F
	}
	if tag != 1 && tag != 3 {
		return false
	}
	// Version byte that follows the length: 3 for tag 1, 4 or 5 for tag 3.
	for _, v := range d[1:4] {
		if (tag == 1 && v == 3) || (tag == 3 && (v == 4 || v == 5)) {
			return true
		}
	}
	return false
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Print displays crypto results.
func Print(r *Result) {
	fmt.Println()
	fmt.Println("  Encryption analysis")
	fmt.Printf("    Entropy:      %.4f bits/byte\n", r.Entropy)
	if r.Verdict != VerdictTooSmall {
		fmt.Printf("    Chi-square:   %.1f (uniform random averages 255)\n", r.ChiSquare)
	}
	fmt.Printf("    Distribution: %s\n", describeVerdict(r.Verdict))
	if r.Container != "" {
		fmt.Printf("    Container:    %s\n", r.Container)
		for _, d := range r.Details {
			fmt.Printf("                  %s\n", d)
		}
	}
	if r.ECBSuspected {
		fmt.Printf("    ECB pattern:  %d repeated 16-byte block(s); ECB-mode encryption is likely\n", r.RepeatedBlocks)
	}
	fmt.Println()
}

func describeVerdict(v Verdict) string {
	switch v {
	case VerdictRandom:
		return "indistinguishable from random (encrypted, random or strongly compressed)"
	case VerdictCompressed:
		return "high entropy but not uniform (typical of compressed data)"
	case VerdictStructured:
		return "structured (not encrypted as a whole)"
	}
	return fmt.Sprintf("too small to test (need at least %d bytes)", minSample)
}
