package packing

import (
	"crypto/rand"
	"strings"
	"testing"
)

func TestDetectTooSmall(t *testing.T) {
	data := make([]byte, 50) // < 100
	r := Detect(data, "PE")
	if r.Detected {
		t.Errorf("expected not detected for tiny input, got %+v", r)
	}
	if r.Confidence != 0 {
		t.Errorf("expected confidence=0, got %f", r.Confidence)
	}
}

func TestDetectUPXMagic(t *testing.T) {
	data := make([]byte, 256)
	// Embed "UPX!" magic
	copy(data[100:104], []byte("UPX!"))
	// Add a known section name too
	copy(data[150:154], []byte("UPX0"))

	r := Detect(data, "PE")
	if !r.Detected {
		t.Fatalf("expected detection, got %+v", r)
	}
	if r.Packer != "UPX" {
		t.Errorf("expected Packer=UPX, got %q", r.Packer)
	}
	if r.Confidence < 0.6 {
		t.Errorf("expected confidence >= 0.6, got %f", r.Confidence)
	}
	if len(r.Indicators) == 0 {
		t.Error("expected at least one indicator")
	}
}

func TestDetectUPXSectionOnly(t *testing.T) {
	data := make([]byte, 256)
	// Section name only
	copy(data[50:54], []byte("UPX0"))

	r := Detect(data, "PE")
	if !r.Detected {
		t.Fatalf("expected detection by section name, got %+v", r)
	}
	if r.Packer != "UPX" {
		t.Errorf("expected Packer=UPX, got %q", r.Packer)
	}
}

func TestDetectVMProtectMagic(t *testing.T) {
	// VMProtect magic: 0xE8 0x00 0x00 0x00 0x00
	data := make([]byte, 256)
	data[100] = 0xE8
	data[101] = 0x00
	data[102] = 0x00
	data[103] = 0x00
	data[104] = 0x00

	r := Detect(data, "PE")
	if !r.Detected {
		t.Fatalf("expected detection, got %+v", r)
	}
	if r.Packer != "VMProtect" {
		t.Errorf("expected Packer=VMProtect, got %q", r.Packer)
	}
}

func TestDetectThemidaSection(t *testing.T) {
	data := make([]byte, 256)
	copy(data[80:88], []byte(".themida"))

	r := Detect(data, "PE")
	if !r.Detected {
		t.Fatalf("expected detection, got %+v", r)
	}
	if r.Packer != "Themida" {
		t.Errorf("expected Packer=Themida, got %q", r.Packer)
	}
}

func TestDetectASPackSection(t *testing.T) {
	data := make([]byte, 256)
	copy(data[80:88], []byte(".aspack"))

	r := Detect(data, "PE")
	if !r.Detected {
		t.Fatalf("expected detection, got %+v", r)
	}
	if r.Packer != "ASPack" {
		t.Errorf("expected Packer=ASPack, got %q", r.Packer)
	}
}

func TestDetectNonPESkipsSectionCheck(t *testing.T) {
	// Section names only match when format=="PE". With other format, only magic matters.
	data := make([]byte, 256)
	copy(data[80:88], []byte("UPX0"))

	r := Detect(data, "ELF")
	// UPX0 section is not enough without magic when format != PE
	if r.Detected && r.Packer == "UPX" {
		t.Errorf("expected no UPX detection for ELF format without magic, got %+v", r)
	}
}

func TestDetectNoMatch(t *testing.T) {
	// Random data that shouldn't match any packer or heuristic
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i % 4) // simple pattern, not high entropy
	}

	r := Detect(data, "PE")
	if r.Detected {
		t.Errorf("expected no detection for non-packed data, got %+v", r)
	}
}

func TestHeuristicDetectionHighEntropy(t *testing.T) {
	// Build data with high entropy code section PLUS enough anti-debug strings
	// to push confidence over the 0.4 detection threshold.
	data := make([]byte, 2048)
	// Insert a function prologue (push ebp; mov ebp, esp) followed by random bytes
	data[100] = 0x55
	data[101] = 0x8B
	data[102] = 0xEC
	randData := make([]byte, 256)
	rand.Read(randData)
	copy(data[103:103+256], randData)
	// Add anti-debug strings to push confidence over the threshold
	anti := []string{
		"IsDebuggerPresent",
		"CheckRemoteDebuggerPresent",
		"NtQueryInformationProcess",
		"GetTickCount",
	}
	off := 400
	for _, s := range anti {
		copy(data[off:], s)
		off += len(s) + 1
	}

	r := heuristicDetection(data)
	if !r.Detected {
		t.Errorf("expected heuristic detection, got %+v", r)
	}
	if r.Packer != "Unknown (heuristic)" {
		t.Errorf("expected Packer='Unknown (heuristic)', got %q", r.Packer)
	}
	if r.Confidence < 0.4 {
		t.Errorf("expected confidence >= 0.4, got %f", r.Confidence)
	}
	if r.Confidence > 0.7 {
		t.Errorf("expected confidence capped at 0.7, got %f", r.Confidence)
	}
}

func TestHeuristicDetectionAntiDebug(t *testing.T) {
	// Build data with several anti-debug strings but no high entropy or obfuscation
	data := make([]byte, 2000)
	// 5 anti-debug patterns
	antiDebug := []string{
		"IsDebuggerPresent",
		"CheckRemoteDebuggerPresent",
		"NtQueryInformationProcess",
		"GetTickCount",
		"QueryPerformanceCounter",
	}
	off := 0
	for _, s := range antiDebug {
		copy(data[off:], s)
		off += len(s) + 1
	}

	r := heuristicDetection(data)
	if !r.Detected {
		t.Errorf("expected heuristic detection, got %+v", r)
	}
}

func TestHeuristicDetectionNoSignals(t *testing.T) {
	// Plain low-entropy data with no signals
	data := make([]byte, 1000)
	for i := range data {
		data[i] = 0x00
	}

	r := heuristicDetection(data)
	if r.Detected {
		t.Errorf("expected no detection, got %+v", r)
	}
}

func TestHasUnusualImports(t *testing.T) {
	// 3+ patterns should return true
	data := []byte("GetTickCount\x00IsDebuggerPresent\x00NtQueryInformationProcess\x00")
	if !hasUnusualImports(data) {
		t.Error("expected hasUnusualImports=true for 3 patterns")
	}

	// < 3 patterns should return false
	data2 := []byte("GetTickCount\x00IsDebuggerPresent\x00")
	if hasUnusualImports(data2) {
		t.Error("expected hasUnusualImports=false for 2 patterns")
	}

	// No patterns
	if hasUnusualImports([]byte("hello world")) {
		t.Error("expected hasUnusualImports=false for no patterns")
	}
}

func TestHasAntiDebug(t *testing.T) {
	// 2+ patterns should return true
	data := []byte("IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00")
	if !hasAntiDebug(data) {
		t.Error("expected hasAntiDebug=true for 2 patterns")
	}

	// 1 pattern
	data2 := []byte("IsDebuggerPresent\x00")
	if hasAntiDebug(data2) {
		t.Error("expected hasAntiDebug=false for 1 pattern")
	}

	// No patterns
	if hasAntiDebug([]byte("foo bar")) {
		t.Error("expected hasAntiDebug=false for no patterns")
	}
}

func TestHasObfuscation(t *testing.T) {
	// Build data with >5% jump bytes
	data := make([]byte, 1000)
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			data[i] = 0xEB
		} else {
			data[i] = 0xE9
		}
	}
	// Fill the rest with 0x00 so total size is 1000 and threshold is 50
	for i := 200; i < 1000; i++ {
		data[i] = 0x00
	}

	if !hasObfuscation(data) {
		t.Error("expected hasObfuscation=true for high jump density")
	}

	// Data with low jump density
	data2 := make([]byte, 1000)
	for i := 0; i < 5; i++ {
		data2[i*100] = 0xEB
	}
	if hasObfuscation(data2) {
		t.Error("expected hasObfuscation=false for low jump density")
	}
}

func TestFindCodeSections(t *testing.T) {
	// Build a buffer with several function prologues
	data := make([]byte, 4096)
	for off := 100; off < 1024; off += 256 {
		data[off] = 0x55
		data[off+1] = 0x8B
		data[off+2] = 0xEC
	}

	sections := findCodeSections(data)
	if len(sections) == 0 {
		t.Fatal("expected to find at least one code section")
	}
	// Verify each section has data
	for i, s := range sections {
		if len(s.Data) == 0 {
			t.Errorf("section %d has no data", i)
		}
		if s.Size != 256 {
			t.Errorf("section %d: expected size=256, got %d", i, s.Size)
		}
	}
}

func TestFindCodeSectionsNone(t *testing.T) {
	// Random data with no prologues
	data := make([]byte, 1024)
	for i := range data {
		data[i] = 0x90 // NOP
	}
	sections := findCodeSections(data)
	if len(sections) != 0 {
		t.Errorf("expected no code sections, got %d", len(sections))
	}
}

func TestFindCodeSectionsCapped(t *testing.T) {
	// Build a buffer with >10 prologues to test the 10-section cap
	data := make([]byte, 16384)
	for off := 0; off < 16000; off += 100 {
		if off+3 < len(data) {
			data[off] = 0x55
			data[off+1] = 0x8B
			data[off+2] = 0xEC
		}
	}

	sections := findCodeSections(data)
	if len(sections) > 10 {
		t.Errorf("expected at most 10 sections (cap), got %d", len(sections))
	}
}

func TestKnownPackersLoaded(t *testing.T) {
	if len(knownPackers) < 10 {
		t.Errorf("expected at least 10 known packers, got %d", len(knownPackers))
	}
	// Verify some well-known packers are present
	names := make(map[string]bool)
	for _, p := range knownPackers {
		names[p.Name] = true
	}
	for _, want := range []string{"UPX", "VMProtect", "Themida", "ASPack", "PECompact", "Armadillo", "Enigma Protector", "MPRESS", "MEW", "FSG", "NsPack", "Petite", "Y0da Protector", "PKLite", "LZEXE"} {
		if !names[want] {
			t.Errorf("expected %q in known packers", want)
		}
	}
}

func TestDetectConfidenceClamped(t *testing.T) {
	// Test that confidence is clamped to 0.95
	data := make([]byte, 256)
	copy(data[100:104], []byte("UPX!"))
	copy(data[150:154], []byte("UPX0"))
	copy(data[160:164], []byte("UPX1"))

	r := Detect(data, "PE")
	if !r.Detected {
		t.Fatal("expected detection")
	}
	if r.Confidence > 0.95 {
		t.Errorf("expected confidence clamped to 0.95, got %f", r.Confidence)
	}
}

func TestDetectIndicatorsNonEmpty(t *testing.T) {
	data := make([]byte, 256)
	copy(data[100:104], []byte("UPX!"))

	r := Detect(data, "PE")
	if !r.Detected {
		t.Fatal("expected detection")
	}
	found := false
	for _, ind := range r.Indicators {
		if strings.Contains(ind, "Magic") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Magic' indicator, got %v", r.Indicators)
	}
}
