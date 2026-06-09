package registry

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Result holds registry analysis results.
type Result struct {
	FileName  string         `json:"file_name"`
	HiveName  string         `json:"hive_name"`
	HiveType  string         `json:"hive_type"`
	Keys      []RegistryKey  `json:"keys"`
	Artifacts []Artifact     `json:"artifacts"`
	Stats     map[string]int `json:"stats"`
}

// RegistryKey represents a registry key.
type RegistryKey struct {
	Path      string    `json:"path"`
	Values    []Value   `json:"values"`
	Timestamp time.Time `json:"timestamp"`
}

// Value represents a registry value.
type Value struct {
	Name string      `json:"name"`
	Type uint32      `json:"type"`
	Data interface{} `json:"data"`
	Size int         `json:"size"`
}

// Artifact represents a forensic artifact.
type Artifact struct {
	Category    string  `json:"category"`
	Description string  `json:"description"`
	Value       string  `json:"value"`
	Confidence  float64 `json:"confidence"`
}

var knownArtifactPaths = map[string]string{
	"Microsoft\\Windows\\CurrentVersion\\Run":                          "Persistence - Auto-start",
	"Microsoft\\Windows\\CurrentVersion\\RunOnce":                      "Persistence - One-time auto-start",
	"Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders":      "User folders",
	"Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders": "User folders (redirected)",
	"Microsoft\\Windows NT\\CurrentVersion\\Winlogon":                  "Winlogon settings",
	"Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer":           "Policy settings",
	"Microsoft\\Windows\\CurrentVersion\\Uninstall":                    "Installed software",
	"SYSTEM\\CurrentControlSet\\Services":                              "Services",
	"SYSTEM\\CurrentControlSet\\Control\\Session Manager":              "Session Manager",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion":                  "Windows version",
	"SYSTEM\\CurrentControlSet\\Control\\ComputerName":                 "Computer name",
	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer":           "Explorer settings",
}

// Hive-specific artifact paths for SAM, SYSTEM, and USER hives.
var samArtifactPaths = map[string]string{
	"SAM\\Domains\\Account\\Users":        "User accounts",
	"SAM\\Domains\\Account\\Users\\Names": "User account names",
	"SAM\\Domains\\Account\\Aliases":      "Local group aliases",
}

var systemArtifactPaths = map[string]string{
	"SYSTEM\\CurrentControlSet\\Services":                            "Services (SYSTEM)",
	"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName": "Computer name",
	"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation":        "Timezone",
	"SYSTEM\\CurrentControlSet\\Control\\Lsa":                        "LSA settings",
	"SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD":                    "LSA JD (anti-hijack)",
	"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1":                 "LSA Skew1 (anti-hijack)",
	"SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG":                   "LSA GBG (anti-hijack)",
	"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data":                  "LSA Data",
	"SYSTEM\\CurrentControlSet\\Control\\ProductOptions":             "Product options",
	"SYSTEM\\CurrentControlSet\\Control\\Windows":                    "Windows settings",
	"SYSTEM\\MountedDevices":                                         "Mounted devices",
	"SYSTEM\\Setup":                                                  "Setup information",
}

var userArtifactPaths = map[string]string{
	"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs":     "Recent documents",
	"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU":         "Run dialog history",
	"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths":     "Typed paths",
	"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery": "Search history",
	"Software\\Microsoft\\Office":                                            "Microsoft Office data",
	"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist":     "UserAssist (program execution)",
	"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MuiCache":       "MUICache (program names)",
	"Software\\Microsoft\\Windows\\Shell\\Bags":                              "Explorer bags (folder views)",
	"Software\\Microsoft\\Windows\\Shell\\MRUList":                           "Shell MRU",
	"Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Recent":          "Recent applets",
}

// addHiveSpecificArtifacts extracts forensic artifacts specific to the hive type.
func addHiveSpecificArtifacts(result *Result) {
	var paths map[string]string

	switch result.HiveType {
	case "SAM":
		paths = samArtifactPaths
	case "SYSTEM":
		paths = systemArtifactPaths
	case "USER":
		paths = userArtifactPaths
	default:
		return
	}

	for _, key := range result.Keys {
		for pattern, category := range paths {
			if strings.Contains(key.Path, pattern) {
				result.Artifacts = append(result.Artifacts, Artifact{
					Category:    category,
					Description: "Hive-specific artifact: " + result.HiveType,
					Value:       key.Path,
					Confidence:  0.85,
				})
			}
		}
	}

	result.Stats["hive_artifacts"] = len(result.Artifacts)
}

// DetectHiveType identifies the registry hive type from its name or path.
func DetectHiveType(fileName, hiveName string) string {
	upper := strings.ToUpper(fileName + hiveName)
	if strings.Contains(upper, "SAM") {
		return "SAM"
	}
	if strings.Contains(upper, "SYSTEM") {
		return "SYSTEM"
	}
	if strings.Contains(upper, "NTUSER") || strings.Contains(upper, "USER.DAT") {
		return "USER"
	}
	if strings.Contains(upper, "SOFTWARE") && !strings.Contains(upper, "SYSTEM") {
		return "SOFTWARE"
	}
	if strings.Contains(upper, "SECURITY") {
		return "SECURITY"
	}
	return "UNKNOWN"
}

// Analyze parses Windows Registry hive data.
func Analyze(data []byte, fileName string) (*Result, error) {
	result := &Result{
		FileName:  fileName,
		Keys:      []RegistryKey{},
		Artifacts: []Artifact{},
		Stats:     make(map[string]int),
	}

	if len(data) < 4096 {
		return result, fmt.Errorf("file too small for registry hive")
	}

	// Check registry signature
	signature := string(data[:4])
	if signature != "regf" {
		return result, fmt.Errorf("not a valid registry hive file")
	}

	// Get hive name
	result.HiveName = strings.TrimRight(string(data[48:68]), "\x00")

	// Detect hive type
	result.HiveType = DetectHiveType(fileName, result.HiveName)

	// Parse root key offset
	rootKeyOffset := binary.LittleEndian.Uint32(data[36:40])

	// Parse keys (simplified)
	parseKeys(data, int(rootKeyOffset), "", result)

	// Add hive-specific artifact detection
	addHiveSpecificArtifacts(result)

	return result, nil
}

func parseKeys(data []byte, offset int, path string, result *Result) {
	if offset <= 0 || offset >= len(data)-16 {
		return
	}

	// Check for nk (named key) record
	if string(data[offset:offset+2]) != "nk" {
		return
	}

	// Parse key name length
	nameLength := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
	if nameLength <= 0 || nameLength > 256 {
		return
	}

	// Parse key name
	name := string(data[offset+4 : offset+4+nameLength])
	fullPath := path + "\\" + name
	if path == "" {
		fullPath = name
	}

	key := RegistryKey{
		Path: fullPath,
	}

	result.Keys = append(result.Keys, key)
	result.Stats["keys"]++

	// Check for known artifacts
	for pattern, category := range knownArtifactPaths {
		if strings.Contains(fullPath, pattern) {
			result.Artifacts = append(result.Artifacts, Artifact{
				Category:    category,
				Description: "Known forensic artifact path",
				Value:       fullPath,
				Confidence:  0.8,
			})
		}
	}
}

// Print displays registry results.
func Print(r *Result) {
	fmt.Println()
	fmt.Printf("  Windows Registry: %s\n", r.FileName)
	fmt.Printf("  Hive Name: %s\n", r.HiveName)
	fmt.Printf("  Hive Type: %s\n", r.HiveType)
	fmt.Printf("  Keys Found: %d\n", len(r.Keys))
	fmt.Println()

	if len(r.Artifacts) > 0 {
		fmt.Println("  Forensic Artifacts:")
		for _, a := range r.Artifacts {
			fmt.Printf("    [%s] %s\n", a.Category, a.Description)
			fmt.Printf("      Path: %s\n", a.Value)
		}
		fmt.Println()
	}
}
