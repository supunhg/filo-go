package nsrl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

// Database holds NSRL hash data.
type Database struct {
	knownHashes map[string]bool
	stats       Stats
}

// Stats holds database statistics.
type Stats struct {
	TotalFiles    int `json:"total_files"`
	TotalHashes   int `json:"total_hashes"`
	MDF5Count     int `json:"md5_count"`
	SHA1Count     int `json:"sha1_count"`
}

// Result holds lookup results.
type Result struct {
	IsKnown   bool   `json:"is_known"`
	HashType  string `json:"hash_type"`
	HashValue string `json:"hash_value"`
}

// NewDatabase creates a new NSRL database.
func NewDatabase() *Database {
	return &Database{
		knownHashes: make(map[string]bool),
	}
}

// LoadFromCSV loads hashes from an NSRL CSV file.
func (d *Database) LoadFromCSV(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Skip header
	if _, err := reader.Read(); err != nil {
		return err
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(record) >= 2 {
			// NSRL CSV format: SHA-1, MD5, ...
			sha1Hash := strings.ToUpper(record[0])
			md5Hash := strings.ToUpper(record[1])

			if sha1Hash != "" {
				d.knownHashes[sha1Hash] = true
				d.stats.SHA1Count++
			}
			if md5Hash != "" {
				d.knownHashes[md5Hash] = true
				d.stats.MDF5Count++
			}
			d.stats.TotalFiles++
		}
	}

	d.stats.TotalHashes = len(d.knownHashes)
	return nil
}

// LoadFromList loads hashes from a simple text file (one hash per line).
func (d *Database) LoadFromList(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		hash := strings.TrimSpace(strings.ToUpper(line))
		if hash != "" {
			d.knownHashes[hash] = true
			d.stats.TotalHashes++
		}
	}

	return nil
}

// Lookup checks if a hash is in the database.
func (d *Database) Lookup(data []byte) *Result {
	// Compute all hashes
	md5Hash := fmt.Sprintf("%x", md5.Sum(data))
	sha1Hash := fmt.Sprintf("%x", sha1.Sum(data))
	sha256Hash := fmt.Sprintf("%x", sha256.Sum256(data))

	// Check each
	if d.knownHashes[strings.ToUpper(md5Hash)] {
		return &Result{IsKnown: true, HashType: "MD5", HashValue: md5Hash}
	}
	if d.knownHashes[strings.ToUpper(sha1Hash)] {
		return &Result{IsKnown: true, HashType: "SHA-1", HashValue: sha1Hash}
	}
	if d.knownHashes[strings.ToUpper(sha256Hash)] {
		return &Result{IsKnown: true, HashType: "SHA-256", HashValue: sha256Hash}
	}

	return &Result{IsKnown: false}
}

// LookupHash checks if a specific hash is in the database.
func (d *Database) LookupHash(hash string) bool {
	return d.knownHashes[strings.ToUpper(hash)]
}

// Stats returns database statistics.
func (d *Database) GetStats() Stats {
	return d.stats
}

// Print displays database statistics.
func PrintStats(db *Database) {
	stats := db.GetStats()
	fmt.Println()
	fmt.Println("  NSRL Database Statistics")
	fmt.Println()
	fmt.Printf("  Total Files: %d\n", stats.TotalFiles)
	fmt.Printf("  Total Hashes: %d\n", stats.TotalHashes)
	fmt.Printf("  MD5 Hashes: %d\n", stats.MDF5Count)
	fmt.Printf("  SHA-1 Hashes: %d\n", stats.SHA1Count)
	fmt.Println()
}
