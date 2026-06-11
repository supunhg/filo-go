package ml

import (
	"strings"
	"testing"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
	if d.profiles == nil {
		t.Error("expected profiles to be initialized")
	}
	// Check that the builtin profiles loaded
	expected := []string{"text", "python", "javascript", "json", "xml", "pdf", "zip"}
	for _, name := range expected {
		if _, ok := d.profiles[name]; !ok {
			t.Errorf("expected builtin profile %q", name)
		}
	}
}

func TestPredictEmptyData(t *testing.T) {
	d := NewDetector()
	p, err := d.Predict([]byte{})
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil prediction")
	}
	if p.Format != "unknown" {
		t.Errorf("Format = %q, want unknown", p.Format)
	}
	if p.Confidence != 0 {
		t.Errorf("Confidence = %f, want 0", p.Confidence)
	}
}

func TestPredictText(t *testing.T) {
	d := NewDetector()
	data := []byte("The quick brown fox jumps over the lazy dog. This is a sample text file that should be recognized as text. The and of to is in for are not be with from have has had was were been being do does did done could would should will shall may might must can could.")
	p, err := d.Predict(data)
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil prediction")
	}
	// Should match one of the builtin text profiles with some confidence
	if p.Confidence <= 0 {
		t.Error("expected some confidence for text data")
	}
}

func TestPredictJSON(t *testing.T) {
	d := NewDetector()
	data := []byte(`{"name": "test", "value": 42, "active": true, "nested": {"key": "value"}, "array": [1, 2, 3]}`)
	p, err := d.Predict(data)
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil prediction")
	}
	if p.Confidence <= 0 {
		t.Error("expected some confidence for JSON data")
	}
}

func TestPredictPDF(t *testing.T) {
	d := NewDetector()
	// Include PDF markers to increase match confidence
	data := []byte("%PDF-1.7\n%Obj 1 0\nThis is PDF content with /Sta and %%EO markers mixed with random bytes abcdefghij1234567890")
	// Pad to make it look more like a real file
	padded := make([]byte, 1024)
	copy(padded, data)
	for i := 64; i < len(padded); i++ {
		padded[i] = byte(i & 0xFF)
	}
	p, err := d.Predict(padded)
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil prediction")
	}
}

func TestPredictZIP(t *testing.T) {
	d := NewDetector()
	// Include ZIP markers
	data := []byte("PK\x03\x04PK\x01\x02PK\x05\x06mimetypeapplication/epub+zip")
	padded := make([]byte, 512)
	copy(padded, data)
	p, err := d.Predict(padded)
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil prediction")
	}
}

func TestPredictReturnsBestMatch(t *testing.T) {
	d := NewDetector()
	// Random binary data should not match any profile well
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i ^ 0xAA)
	}
	p, err := d.Predict(data)
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil prediction")
	}
	// Confidence should be reasonable (not necessarily 0, since the best match
	// still has some similarity)
	if p.Confidence < 0 || p.Confidence > 1 {
		t.Errorf("Confidence out of range: %f", p.Confidence)
	}
}

func TestExtractFeatures(t *testing.T) {
	data := []byte("Hello, World! This is a test of feature extraction.")
	f := extractFeatures(data)
	if f == nil {
		t.Fatal("expected non-nil features")
	}
	if f.Entropy <= 0 {
		t.Error("expected entropy > 0 for non-empty data")
	}
	if f.Entropy > 8 {
		t.Errorf("entropy should be <= 8, got %f", f.Entropy)
	}
	if f.PrintRatio <= 0 {
		t.Error("expected print ratio > 0 for printable text")
	}
	if f.NullRatio != 0 {
		t.Error("expected null ratio = 0 for non-null data")
	}
	if len(f.HeaderBytes) == 0 {
		t.Error("expected header bytes to be populated")
	}
	if f.HighByteRatio < 0 {
		t.Error("expected high byte ratio >= 0")
	}
	if len(f.Ngrams) == 0 {
		t.Error("expected ngrams to be populated")
	}
}

func TestExtractFeaturesEmptyData(t *testing.T) {
	f := extractFeatures([]byte{})
	if f == nil {
		t.Fatal("expected non-nil features even for empty data")
	}
	// HeaderBytes for empty data should be 0 length
	if len(f.HeaderBytes) != 0 {
		t.Errorf("expected empty header bytes, got %d", len(f.HeaderBytes))
	}
}

func TestExtractFeaturesBinaryData(t *testing.T) {
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 256)
	}
	f := extractFeatures(data)
	if f == nil {
		t.Fatal("expected non-nil features")
	}
	if f.Entropy <= 0 {
		t.Error("expected entropy > 0")
	}
}

func TestCompareFeatures(t *testing.T) {
	d := NewDetector()
	profile := d.profiles["text"]
	if profile == nil {
		t.Fatal("text profile not found")
	}

	// Create features that exactly match the text profile
	f := &Features{
		Entropy:       profile.AvgEntropy,
		PrintRatio:    profile.AvgPrintRatio,
		NullRatio:     0,
		HighByteRatio: 0,
		Ngrams:        make(map[string]int),
	}
	for ngram := range profile.CommonNgrams {
		f.Ngrams[ngram] = 1
	}

	score := compareFeatures(f, profile)
	if score <= 0 {
		t.Error("expected positive score for matching features")
	}
	if score > 1 {
		t.Errorf("score should be <= 1, got %f", score)
	}
}

func TestCompareFeaturesZeroEntropy(t *testing.T) {
	profile := &Profile{
		Format:        "test",
		AvgEntropy:    0,
		AvgPrintRatio: 0.5,
		CommonNgrams:  map[string]int{"abc": 1},
	}
	f := &Features{
		Entropy:    0,
		PrintRatio: 0.5,
		Ngrams:     map[string]int{"abc": 1},
	}
	score := compareFeatures(f, profile)
	if score <= 0 {
		t.Error("expected non-zero score even with zero entropy")
	}
}

func TestCompareFeaturesEmptyProfileNgrams(t *testing.T) {
	profile := &Profile{
		Format:        "test",
		AvgEntropy:    4.0,
		AvgPrintRatio: 0.8,
		CommonNgrams:  nil, // empty
	}
	f := &Features{
		Entropy:    4.0,
		PrintRatio: 0.8,
		Ngrams:     map[string]int{"abc": 1},
	}
	score := compareFeatures(f, profile)
	if score <= 0 {
		t.Error("expected non-zero score with empty profile ngrams")
	}
}

func TestPrint(t *testing.T) {
	// Should not panic with various predictions
	cases := []*Prediction{
		{Format: "unknown", Confidence: 0},
		{Format: "text", Confidence: 0.5},
		{Format: "json", Confidence: 0.8},
	}
	for _, p := range cases {
		Print(p)
	}
}

func TestPredictionStruct(t *testing.T) {
	p := &Prediction{
		Format:     "test",
		Confidence: 0.75,
	}
	if p.Format != "test" {
		t.Error("Format not set")
	}
	if p.Confidence != 0.75 {
		t.Error("Confidence not set")
	}
}

func TestProfileStruct(t *testing.T) {
	p := &Profile{
		Format:        "test",
		AvgEntropy:    4.5,
		AvgPrintRatio: 0.85,
		CommonNgrams:  map[string]int{"the": 10},
		Patterns:      [][]byte{[]byte("pattern")},
	}
	if p.Format != "test" {
		t.Error("Format not set")
	}
	if len(p.CommonNgrams) != 1 {
		t.Error("CommonNgrams not set")
	}
	if len(p.Patterns) != 1 {
		t.Error("Patterns not set")
	}
}

func TestFeaturesStruct(t *testing.T) {
	f := &Features{
		Entropy:       4.5,
		PrintRatio:    0.85,
		NullRatio:     0.1,
		HighByteRatio: 0.05,
		Ngrams:        map[string]int{"test": 5},
		HeaderBytes:   []byte{0x00, 0x01, 0x02},
	}
	if f.Entropy != 4.5 {
		t.Error("Entropy not set")
	}
	if f.HeaderBytes[0] != 0x00 {
		t.Error("HeaderBytes not set")
	}
}

func TestBuiltinProfilesHaveNgrams(t *testing.T) {
	d := NewDetector()
	// Each builtin profile should have CommonNgrams populated
	for name, profile := range d.profiles {
		if len(profile.CommonNgrams) == 0 {
			t.Errorf("profile %q has no CommonNgrams", name)
		}
	}
}

func TestBuiltinProfilesHaveValidEntropy(t *testing.T) {
	d := NewDetector()
	for name, profile := range d.profiles {
		if profile.AvgEntropy < 0 || profile.AvgEntropy > 8 {
			t.Errorf("profile %q has invalid entropy %f", name, profile.AvgEntropy)
		}
		if profile.AvgPrintRatio < 0 || profile.AvgPrintRatio > 1 {
			t.Errorf("profile %q has invalid print ratio %f", name, profile.AvgPrintRatio)
		}
	}
}

func TestPredictWithNilDetector(t *testing.T) {
	d := &Detector{profiles: map[string]*Profile{
		"test": {
			Format:        "test",
			AvgEntropy:    5.0,
			AvgPrintRatio: 0.5,
			CommonNgrams:  map[string]int{"abc": 1},
		},
	}}
	p, err := d.Predict([]byte("abc abc abc"))
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil prediction")
	}
}

func TestPredictScoreClamping(t *testing.T) {
	// Score should be clamped to [0, 1]
	d := NewDetector()
	profile := d.profiles["text"]
	f := &Features{
		Entropy:       -10, // far below
		PrintRatio:    2.0, // above 1
		NullRatio:     0,
		HighByteRatio: 0,
		Ngrams:        map[string]int{"the": 1000},
	}
	score := compareFeatures(f, profile)
	if score < 0 {
		t.Error("score should be >= 0")
	}
	if score > 1 {
		t.Error("score should be <= 1")
	}
	_ = strings.Contains // ensure strings import is used
}
