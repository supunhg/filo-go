package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Cache provides file analysis caching using BoltDB.
type Cache struct {
	db *bolt.DB
}

// CacheEntry represents a cached analysis result.
type CacheEntry struct {
	FilePath  string      `json:"file_path"`
	FileSize  int64       `json:"file_size"`
	SHA256    string      `json:"sha256"`
	Result    interface{} `json:"result"`
	Timestamp time.Time   `json:"timestamp"`
	Version   string      `json:"version"`
}

var (
	analysisBucket = []byte("analysis")
	hashBucket     = []byte("hash")
	metaBucket     = []byte("meta")
)

// New creates a new cache instance.
func New(dbPath string) (*Cache, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open cache: %w", err)
	}

	// Create buckets
	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{analysisBucket, hashBucket, metaBucket} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create buckets: %w", err)
	}

	return &Cache{db: db}, nil
}

// Close closes the cache database.
func (c *Cache) Close() error {
	return c.db.Close()
}

// Get retrieves a cached analysis result.
// Returns nil if not found or if the file has changed.
func (c *Cache) Get(filePath string) (*CacheEntry, error) {
	// Get current file hash
	hash, err := FileHash(filePath)
	if err != nil {
		return nil, err
	}

	var entry *CacheEntry
	err = c.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(analysisBucket)
		data := b.Get([]byte(hash))
		if data == nil {
			return nil
		}

		entry = &CacheEntry{}
		return json.Unmarshal(data, entry)
	})

	return entry, err
}

// Set stores an analysis result in the cache.
func (c *Cache) Set(filePath string, result interface{}) error {
	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	hash, err := FileHash(filePath)
	if err != nil {
		return err
	}

	entry := &CacheEntry{
		FilePath:  filePath,
		FileSize:  info.Size(),
		SHA256:    hash,
		Result:    result,
		Timestamp: time.Now(),
		Version:   "0.4.0",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(analysisBucket)
		return b.Put([]byte(hash), data)
	})
}

// Delete removes a cached entry.
func (c *Cache) Delete(filePath string) error {
	hash, err := FileHash(filePath)
	if err != nil {
		return err
	}

	return c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(analysisBucket)
		return b.Delete([]byte(hash))
	})
}

// Clear removes all cached entries.
func (c *Cache) Clear() error {
	return c.db.Update(func(tx *bolt.Tx) error {
		// Delete and recreate the bucket
		if err := tx.DeleteBucket(analysisBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucket(analysisBucket)
		return err
	})
}

// Stats returns cache statistics.
func (c *Cache) Stats() (map[string]interface{}, error) {
	stats := map[string]interface{}{}

	err := c.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(analysisBucket)
		stats["entries"] = b.Stats().KeyN
		return nil
	})

	return stats, err
}

// FileHash computes SHA256 hash of a file.
func FileHash(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), nil
}

// IsExpired checks if a cache entry is expired.
func IsExpired(entry *CacheEntry, maxAge time.Duration) bool {
	return time.Since(entry.Timestamp) > maxAge
}
