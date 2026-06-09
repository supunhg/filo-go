package registry

import (
	"testing"
	"time"
)

func TestAnalyze(t *testing.T) {
	// Test with empty data
	_, err := Analyze([]byte{}, "test.dat")
	if err == nil {
		t.Error("Expected error for empty data")
	}

	// Test with too small data
	_, err = Analyze(make([]byte, 100), "test.dat")
	if err == nil {
		t.Error("Expected error for small data")
	}

	// Test with invalid signature
	_, err = Analyze(make([]byte, 4096), "test.dat")
	if err == nil {
		t.Error("Expected error for invalid signature")
	}
}

func TestAnalyze_ValidSignature(t *testing.T) {
	// Create a minimal valid registry header
	data := make([]byte, 4096)
	copy(data[:4], "regf")
	copy(data[48:68], "TestHive")

	_, err := Analyze(data, "test.dat")
	// Should not error on valid signature
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestDetectHiveType(t *testing.T) {
	tests := []struct {
		fileName string
		hiveName string
		want     string
	}{
		{"SAM", "", "SAM"},
		{"SYSTEM", "", "SYSTEM"},
		{"NTUSER.DAT", "", "USER"},
		{"USER.DAT", "", "USER"},
		{"SOFTWARE", "", "SOFTWARE"},
		{"SECURITY", "", "SECURITY"},
		{"UNKNOWN.dat", "", "UNKNOWN"},
		{"", "SAM", "SAM"},
		{"", "SYSTEM", "SYSTEM"},
		{"test_sam.dat", "", "SAM"},
		{"test_system.dat", "", "SYSTEM"},
	}

	for _, tt := range tests {
		t.Run(tt.fileName+tt.hiveName, func(t *testing.T) {
			got := DetectHiveType(tt.fileName, tt.hiveName)
			if got != tt.want {
				t.Errorf("DetectHiveType(%q, %q) = %v, want %v", tt.fileName, tt.hiveName, got, tt.want)
			}
		})
	}
}

func TestRegistryKeyCreation(t *testing.T) {
	key := RegistryKey{
		Path:      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft",
		Timestamp: time.Now(),
		Values: []Value{
			{Name: "TestValue", Type: 1, Data: "TestData", Size: 8},
		},
	}

	if key.Path != "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft" {
		t.Errorf("Expected path HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft, got %s", key.Path)
	}

	if len(key.Values) != 1 {
		t.Errorf("Expected 1 value, got %d", len(key.Values))
	}
}

func TestParseKeys(t *testing.T) {
	result := &Result{
		FileName:  "test.dat",
		Keys:      []RegistryKey{},
		Artifacts: []Artifact{},
		Stats:     make(map[string]int),
	}

	// Test with invalid offset
	parseKeys([]byte{}, 0, "", result)
	if len(result.Keys) != 0 {
		t.Error("Expected no keys from invalid offset")
	}

	// Test with offset beyond data
	parseKeys([]byte("test"), 100, "", result)
	if len(result.Keys) != 0 {
		t.Error("Expected no keys from offset beyond data")
	}
}

func TestAddHiveSpecificArtifacts(t *testing.T) {
	result := &Result{
		FileName:  "SAM",
		HiveType:  "SAM",
		Keys: []RegistryKey{
			{Path: "SAM\\Domains\\Account\\Users"},
		},
		Artifacts: []Artifact{},
		Stats:     make(map[string]int),
	}

	addHiveSpecificArtifacts(result)

	if len(result.Artifacts) == 0 {
		t.Error("Expected SAM-specific artifacts")
	}

	if result.Stats["hive_artifacts"] == 0 {
		t.Error("Expected hive_artifacts stat")
	}
}

func TestAddHiveSpecificArtifacts_SYSTEM(t *testing.T) {
	result := &Result{
		FileName:  "SYSTEM",
		HiveType:  "SYSTEM",
		Keys: []RegistryKey{
			{Path: "SYSTEM\\CurrentControlSet\\Services"},
		},
		Artifacts: []Artifact{},
		Stats:     make(map[string]int),
	}

	addHiveSpecificArtifacts(result)

	if len(result.Artifacts) == 0 {
		t.Error("Expected SYSTEM-specific artifacts")
	}
}

func TestAddHiveSpecificArtifacts_USER(t *testing.T) {
	result := &Result{
		FileName:  "NTUSER.DAT",
		HiveType:  "USER",
		Keys: []RegistryKey{
			{Path: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"},
		},
		Artifacts: []Artifact{},
		Stats:     make(map[string]int),
	}

	addHiveSpecificArtifacts(result)

	if len(result.Artifacts) == 0 {
		t.Error("Expected USER-specific artifacts")
	}
}

func TestKnownArtifactPaths(t *testing.T) {
	// Test that all known paths are accessible
	for pattern, category := range knownArtifactPaths {
		if pattern == "" || category == "" {
			t.Errorf("Empty pattern or category: %s -> %s", pattern, category)
		}
	}
}

func TestPrint(t *testing.T) {
	result := &Result{
		FileName:  "test.dat",
		HiveName:  "TestHive",
		HiveType:  "SOFTWARE",
		Keys:      []RegistryKey{{Path: "TestKey"}},
		Artifacts: []Artifact{{Category: "Test", Description: "Test artifact"}},
		Stats:     map[string]int{"keys": 1},
	}

	// Test that Print doesn't panic
	Print(result)
}

func TestValueType(t *testing.T) {
	value := Value{
		Name: "TestValue",
		Type: 1, // REG_SZ
		Data: "TestData",
		Size: 8,
	}

	if value.Type != 1 {
		t.Errorf("Expected type 1, got %d", value.Type)
	}

	if value.Data != "TestData" {
		t.Errorf("Expected data TestData, got %v", value.Data)
	}
}

func TestArtifactCreation(t *testing.T) {
	artifact := Artifact{
		Category:    "Persistence",
		Description: "Auto-start entry",
		Value:       "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		Confidence:  0.9,
	}

	if artifact.Category != "Persistence" {
		t.Errorf("Expected category Persistence, got %s", artifact.Category)
	}

	if artifact.Confidence != 0.9 {
		t.Errorf("Expected confidence 0.9, got %f", artifact.Confidence)
	}
}

func TestHiveSpecificPaths(t *testing.T) {
	// Test SAM paths
	if _, ok := samArtifactPaths["SAM\\Domains\\Account\\Users"]; !ok {
		t.Error("Missing SAM artifact path")
	}

	// Test SYSTEM paths
	if _, ok := systemArtifactPaths["SYSTEM\\CurrentControlSet\\Services"]; !ok {
		t.Error("Missing SYSTEM artifact path")
	}

	// Test USER paths
	if _, ok := userArtifactPaths["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"]; !ok {
		t.Error("Missing USER artifact path")
	}
}
