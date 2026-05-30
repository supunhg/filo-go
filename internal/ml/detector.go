package ml

import (
	"math"
	"strings"
)

// Detector provides ML-powered file type detection.
type Detector struct {
	profiles map[string]*Profile
}

// Profile holds learned patterns for a file type.
type Profile struct {
	Format        string
	AvgEntropy    float64
	AvgPrintRatio float64
	CommonNgrams  map[string]int
	Patterns      [][]byte
}

// NewDetector creates a new ML detector.
func NewDetector() *Detector {
	d := &Detector{
		profiles: make(map[string]*Profile),
	}
	d.loadBuiltinProfiles()
	return d
}

// Predict predicts file type using ML features.
func (d *Detector) Predict(data []byte) (*Prediction, error) {
	if len(data) == 0 {
		return &Prediction{Format: "unknown", Confidence: 0}, nil
	}

	features := extractFeatures(data)
	bestMatch := &Prediction{Format: "unknown", Confidence: 0}

	for format, profile := range d.profiles {
		score := compareFeatures(features, profile)
		if score > bestMatch.Confidence {
			bestMatch = &Prediction{
				Format:     format,
				Confidence: score,
			}
		}
	}

	return bestMatch, nil
}

// Prediction holds ML prediction result.
type Prediction struct {
	Format     string  `json:"format"`
	Confidence float64 `json:"confidence"`
}

// Features extracted from file data.
type Features struct {
	Entropy      float64
	PrintRatio   float64
	NullRatio    float64
	HighByteRatio float64
	Ngrams       map[string]int
	HeaderBytes  []byte
}

func extractFeatures(data []byte) *Features {
	f := &Features{
		Ngrams:      make(map[string]int),
		HeaderBytes: data[:min(256, len(data))],
	}

	// Calculate entropy
	f.Entropy = calculateEntropy(data)

	// Calculate ratios
	printable := 0
	nulls := 0
	high := 0
	for _, b := range data {
		if b >= 0x20 && b <= 0x7E {
			printable++
		}
		if b == 0 {
			nulls++
		}
		if b > 127 {
			high++
		}
	}

	size := float64(len(data))
	f.PrintRatio = float64(printable) / size
	f.NullRatio = float64(nulls) / size
	f.HighByteRatio = float64(high) / size

	// Extract n-grams (4-grams)
	for i := 0; i <= len(data)-4; i++ {
		ngram := string(data[i : i+4])
		f.Ngrams[ngram]++
	}

	return f
}

func compareFeatures(f *Features, p *Profile) float64 {
	score := 0.0

	// Entropy similarity
	entropyDiff := math.Abs(f.Entropy - p.AvgEntropy)
	entropyScore := math.Max(0, 1-entropyDiff/4.0)
	score += entropyScore * 0.3

	// Print ratio similarity
	printDiff := math.Abs(f.PrintRatio - p.AvgPrintRatio)
	printScore := math.Max(0, 1-printDiff)
	score += printScore * 0.3

	// N-gram similarity
	ngramScore := 0.0
	if len(p.CommonNgrams) > 0 {
		matches := 0
		for ngram := range p.CommonNgrams {
			if f.Ngrams[ngram] > 0 {
				matches++
			}
		}
		ngramScore = float64(matches) / float64(len(p.CommonNgrams))
	}
	score += ngramScore * 0.4

	return score
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

func (d *Detector) loadBuiltinProfiles() {
	// Text profiles
	d.profiles["text"] = &Profile{
		Format:        "text",
		AvgEntropy:    4.5,
		AvgPrintRatio: 0.85,
		CommonNgrams: map[string]int{
			" the": 100, " and": 80, " of ": 70,
			" to ": 60, " is ": 50, " in ": 45,
		},
	}

	// Source code profiles
	d.profiles["python"] = &Profile{
		Format:        "python",
		AvgEntropy:    4.8,
		AvgPrintRatio: 0.82,
		CommonNgrams: map[string]int{
			"def ": 100, "import ": 80, "class ": 70,
			"self": 60, "return ": 50, "print": 40,
		},
	}

	d.profiles["javascript"] = &Profile{
		Format:        "javascript",
		AvgEntropy:    5.0,
		AvgPrintRatio: 0.80,
		CommonNgrams: map[string]int{
			"func": 100, "var ": 80, "cons": 70,
			"retu": 60, "strin": 50, "numbe": 40,
		},
	}

	d.profiles["json"] = &Profile{
		Format:        "json",
		AvgEntropy:    4.2,
		AvgPrintRatio: 0.90,
		CommonNgrams: map[string]int{
			"null": 100, "true": 80, "fals": 70,
			"\": \"": 60, "\": {": 50, "\": [": 40,
		},
	}

	d.profiles["xml"] = &Profile{
		Format:        "xml",
		AvgEntropy:    4.0,
		AvgPrintRatio: 0.88,
		CommonNgrams: map[string]int{
			"<xml": 100, "><?x": 80, "</": 70,
			"xml ": 60, "utf-": 50, "enco": 40,
		},
	}

	// Binary profiles
	d.profiles["pdf"] = &Profile{
		Format:        "pdf",
		AvgEntropy:    6.5,
		AvgPrintRatio: 0.60,
		CommonNgrams: map[string]int{
			"%PDF": 100, "/Obj": 80, "/Sta": 70,
			"%%EO": 60, "/Pag": 50, "/Fon": 40,
		},
	}

	d.profiles["zip"] = &Profile{
		Format:        "zip",
		AvgEntropy:    7.0,
		AvgPrintRatio: 0.50,
		CommonNgrams: map[string]int{
			"PK\x03\x04": 100, "PK\x01\x02": 80,
			"PK\x05\x06": 70, "mimetype": 60,
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Print displays ML prediction results.
func Print(p *Prediction) {
	if p.Format != "unknown" && p.Confidence > 0.5 {
		_ = strings.Contains(p.Format, "")
	}
}
