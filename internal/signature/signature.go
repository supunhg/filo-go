// Package signature finds files embedded anywhere inside a byte stream.
//
// Every signature pairs a magic number with a structural validator, so a
// candidate is reported only when the bytes that follow the magic parse as
// the claimed format. Validators also compute the embedded file's size when
// the format makes that possible, which lets the scanner skip matches that
// fall inside a file it has already identified (for example the per-entry
// headers inside a ZIP archive).
package signature

import (
	"sort"
)

// Match is one embedded file found by Scan.
type Match struct {
	// Offset is the position of the embedded file's first byte.
	Offset int64 `json:"offset"`
	// Size is the embedded file's length in bytes, or 0 when the format does
	// not allow it to be computed without fully decoding the payload.
	Size int64 `json:"size,omitempty"`
	// Format is a short, stable identifier such as "png" or "zip".
	Format string `json:"format"`
	// MIME is the format's media type, when one is registered.
	MIME string `json:"mime,omitempty"`
	// Description is a human-readable summary of the parsed header.
	Description string `json:"description"`
}

// End returns the offset one past the last byte of the match, or -1 when the
// size is unknown.
func (m Match) End() int64 {
	if m.Size <= 0 {
		return -1
	}
	return m.Offset + m.Size
}

// Options tunes Scan.
type Options struct {
	// IncludeNested reports matches that start inside an earlier match of
	// known size. By default they are suppressed.
	IncludeNested bool
	// Limit stops the scan after this many matches. Zero means no limit.
	Limit int
	// Formats restricts the scan to these format identifiers. Empty means all.
	Formats []string
}

// checkFunc validates the bytes at a candidate offset. d starts at the
// embedded file's first byte and extends to the end of the scanned data.
// It returns the description, the size (0 when unknown) and whether the
// candidate is genuine.
type checkFunc func(d []byte) (desc string, size int64, ok bool)

type sig struct {
	format string
	mime   string
	magic  []byte
	// at is the offset of magic relative to the start of the file, for
	// formats whose identifying bytes are not at the very beginning.
	at    int
	check checkFunc
}

// Formats lists the identifiers of every format Scan can detect.
func Formats() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range sigs {
		if !seen[s.format] {
			seen[s.format] = true
			out = append(out, s.format)
		}
	}
	sort.Strings(out)
	return out
}

// index maps the first two magic bytes to the signatures that start with them.
var index [65536][]int

func init() {
	for i, s := range sigs {
		if len(s.magic) < 2 {
			panic("signature: magic shorter than 2 bytes for " + s.format)
		}
		k := int(s.magic[0])<<8 | int(s.magic[1])
		index[k] = append(index[k], i)
	}
}

// Scan returns every embedded file found in data, ordered by offset.
func Scan(data []byte, opts Options) []Match {
	var allow map[string]bool
	if len(opts.Formats) > 0 {
		allow = make(map[string]bool, len(opts.Formats))
		for _, f := range opts.Formats {
			allow[f] = true
		}
	}

	var matches []Match
	var coveredUntil int64 = -1
	n := len(data)
	for i := 0; i+1 < n; i++ {
		cands := index[int(data[i])<<8|int(data[i+1])]
		if len(cands) == 0 {
			continue
		}
		for _, ci := range cands {
			s := &sigs[ci]
			start := i - s.at
			if start < 0 || i+len(s.magic) > n || !hasPrefix(data[i:], s.magic) {
				continue
			}
			if allow != nil && !allow[s.format] {
				continue
			}
			if !opts.IncludeNested && int64(start) < coveredUntil {
				continue
			}
			desc, size, ok := s.check(data[start:])
			if !ok {
				continue
			}
			if size > int64(n-start) {
				size = int64(n - start)
			}
			m := Match{Offset: int64(start), Size: size, Format: s.format, MIME: s.mime, Description: desc}
			matches = append(matches, m)
			if end := m.End(); end > coveredUntil {
				coveredUntil = end
			}
			if opts.Limit > 0 && len(matches) >= opts.Limit {
				sortMatches(matches)
				return matches
			}
			break
		}
	}
	sortMatches(matches)
	return matches
}

// Identify reports the format of data when its first bytes match a known
// signature.
func Identify(data []byte) (Match, bool) {
	if len(data) < 2 {
		return Match{}, false
	}
	for _, s := range sigs {
		if s.at+len(s.magic) > len(data) || !hasPrefix(data[s.at:], s.magic) {
			continue
		}
		if desc, size, ok := s.check(data); ok {
			return Match{Size: size, Format: s.format, MIME: s.mime, Description: desc}, true
		}
	}
	return Match{}, false
}

func sortMatches(m []Match) {
	// Signatures with a non-zero magic offset (tar, ISO-BMFF) can be found
	// after a later-starting match, so restore offset order.
	sort.SliceStable(m, func(a, b int) bool { return m[a].Offset < m[b].Offset })
}

func hasPrefix(d, p []byte) bool {
	if len(d) < len(p) {
		return false
	}
	for i := range p {
		if d[i] != p[i] {
			return false
		}
	}
	return true
}
