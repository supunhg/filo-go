// Package version holds build metadata for the filo binary.
//
// Release builds set these variables with -ldflags, for example:
//
//	-X github.com/supunhg/filo-go/internal/version.Version=v0.6.0
//
// Builds made with `go install module@version` fall back to the module
// version recorded in the binary's build info.
package version

import "runtime/debug"

var (
	// Version is the semantic version of this build.
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = ""
	// Date is the build date in RFC 3339 format.
	Date = ""
)

func init() {
	if Version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		Version = v
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if Commit == "" {
				Commit = s.Value
			}
		case "vcs.time":
			if Date == "" {
				Date = s.Value
			}
		}
	}
}

// String returns a one-line human-readable description of the build.
func String() string {
	s := "filo " + Version
	if Commit != "" {
		c := Commit
		if len(c) > 12 {
			c = c[:12]
		}
		s += " (" + c
		if Date != "" {
			s += ", " + Date
		}
		s += ")"
	}
	return s
}
