package lineage

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Record represents a lineage record.
type Record struct {
	OriginalHash string    `json:"original_hash"`
	ResultHash   string    `json:"result_hash"`
	Operation    string    `json:"operation"`
	Timestamp    time.Time `json:"timestamp"`
	FilePath     string    `json:"file_path,omitempty"`
	Description  string    `json:"description,omitempty"`
}

// Tracker manages lineage tracking.
type Tracker struct {
	db *bolt.DB
}

// NewTracker creates a new lineage tracker.
func NewTracker(dbPath string) (*Tracker, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open lineage database: %w", err)
	}

	// Create bucket if not exists
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("lineage"))
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &Tracker{db: db}, nil
}

// Close closes the database.
func (t *Tracker) Close() error {
	return t.db.Close()
}

// Record records a transformation.
func (t *Tracker) Record(originalData, resultData []byte, operation, filePath, description string) error {
	originalHash := computeHash(originalData)
	resultHash := computeHash(resultData)

	record := Record{
		OriginalHash: originalHash,
		ResultHash:   resultHash,
		Operation:    operation,
		Timestamp:    time.Now(),
		FilePath:     filePath,
		Description:  description,
	}

	return t.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("lineage"))
		key := []byte(fmt.Sprintf("%s:%s:%d", originalHash, resultHash, record.Timestamp.UnixNano()))
		return bucket.Put(key, []byte(fmt.Sprintf("%s|%s|%s|%s|%s",
			record.OriginalHash, record.ResultHash, record.Operation,
			record.Timestamp.Format(time.RFC3339), record.FilePath)))
	})
}

// RecordFromFile records a transformation from file paths.
func (t *Tracker) RecordFromFile(originalPath, resultPath, operation, description string) error {
	originalData := readFile(originalPath)
	resultData := readFile(resultPath)
	return t.Record(originalData, resultData, operation, originalPath, description)
}

// GetByHash gets all records for a hash.
func (t *Tracker) GetByHash(hash string) ([]Record, error) {
	var records []Record

	err := t.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("lineage"))
		return bucket.ForEach(func(k, v []byte) error {
			record := parseRecord(v)
			if record.OriginalHash == hash || record.ResultHash == hash {
				records = append(records, record)
			}
			return nil
		})
	})

	return records, err
}

// GetDescendants gets all files derived from a hash.
func (t *Tracker) GetDescendants(hash string) ([]Record, error) {
	var records []Record

	err := t.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("lineage"))
		return bucket.ForEach(func(k, v []byte) error {
			record := parseRecord(v)
			if record.OriginalHash == hash {
				records = append(records, record)
			}
			return nil
		})
	})

	return records, err
}

// GetAncestors gets all files a hash was derived from.
func (t *Tracker) GetAncestors(hash string) ([]Record, error) {
	var records []Record

	err := t.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("lineage"))
		return bucket.ForEach(func(k, v []byte) error {
			record := parseRecord(v)
			if record.ResultHash == hash {
				records = append(records, record)
			}
			return nil
		})
	})

	return records, err
}

// GetFullChain gets the complete chain of custody.
func (t *Tracker) GetFullChain(hash string) ([]Record, error) {
	ancestors, err := t.GetAncestors(hash)
	if err != nil {
		return nil, err
	}

	descendants, err := t.GetDescendants(hash)
	if err != nil {
		return nil, err
	}

	// Combine and deduplicate
	seen := make(map[string]bool)
	var chain []Record

	for _, r := range append(ancestors, descendants...) {
		key := fmt.Sprintf("%s:%s", r.OriginalHash, r.ResultHash)
		if !seen[key] {
			seen[key] = true
			chain = append(chain, r)
		}
	}

	return chain, nil
}

// GetStats returns database statistics.
func (t *Tracker) GetStats() (map[string]interface{}, error) {
	stats := map[string]interface{}{}

	err := t.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("lineage"))
		stats["total_records"] = bucket.Stats().KeyN

		operations := make(map[string]int)
		var minTime, maxTime time.Time

		err := bucket.ForEach(func(k, v []byte) error {
			record := parseRecord(v)
			operations[record.Operation]++
			if minTime.IsZero() || record.Timestamp.Before(minTime) {
				minTime = record.Timestamp
			}
			if maxTime.IsZero() || record.Timestamp.After(maxTime) {
				maxTime = record.Timestamp
			}
			return nil
		})

		stats["operations"] = operations
		if !minTime.IsZero() {
			stats["earliest"] = minTime
			stats["latest"] = maxTime
		}

		return err
	})

	return stats, err
}

// ClearAll clears all records.
func (t *Tracker) ClearAll() error {
	return t.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket([]byte("lineage"))
	})
}

func computeHash(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func parseRecord(data []byte) Record {
	parts := splitN(string(data), "|", 5)
	record := Record{}
	if len(parts) >= 1 {
		record.OriginalHash = parts[0]
	}
	if len(parts) >= 2 {
		record.ResultHash = parts[1]
	}
	if len(parts) >= 3 {
		record.Operation = parts[2]
	}
	if len(parts) >= 4 {
		if t, err := time.Parse(time.RFC3339, parts[3]); err == nil {
			record.Timestamp = t
		}
	}
	if len(parts) >= 5 {
		record.FilePath = parts[4]
	}
	return record
}

func splitN(s, sep string, n int) []string {
	var result []string
	for i := 0; i < n-1; i++ {
		idx := indexOf(s, sep)
		if idx < 0 {
			result = append(result, s)
			return result
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	result = append(result, s)
	return result
}

func indexOf(s, sep string) int {
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

func readFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

// Print displays lineage results.
func Print(records []Record) {
	fmt.Println()
	if len(records) == 0 {
		fmt.Println("  No lineage records found")
	} else {
		fmt.Printf("  Found %d record(s):\n\n", len(records))
		for _, r := range records {
			fmt.Printf("    Operation: %s\n", r.Operation)
			fmt.Printf("    Original:  %s\n", r.OriginalHash[:16])
			fmt.Printf("    Result:    %s\n", r.ResultHash[:16])
			fmt.Printf("    Time:      %s\n", r.Timestamp.Format(time.RFC3339))
			if r.FilePath != "" {
				fmt.Printf("    File:      %s\n", r.FilePath)
			}
			fmt.Println()
		}
	}
}
