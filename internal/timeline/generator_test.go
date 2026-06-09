package timeline

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tl := New()
	if tl == nil {
		t.Error("Expected non-nil timeline")
	}
}

func TestAdd(t *testing.T) {
	tl := New()

	tl.Add(time.Now(), "test", "event", "detail", "category")

	if len(tl.Entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(tl.Entries))
	}
}

func TestSort(t *testing.T) {
	tl := New()

	// Add events out of order
	tl.Add(time.Now().Add(time.Hour), "test", "event2", "detail", "cat")
	tl.Add(time.Now(), "test", "event1", "detail", "cat")

	tl.Sort()

	if tl.Entries[0].Event != "event1" {
		t.Errorf("Expected event1 first, got %s", tl.Entries[0].Event)
	}
}

func TestFilterByTime(t *testing.T) {
	tl := New()

	now := time.Now()
	tl.Add(now, "test", "event1", "detail", "cat")
	tl.Add(now.Add(time.Hour), "test", "event2", "detail", "cat")

	// Filter to only include first event
	filtered := tl.FilterByTime(now.Add(-time.Minute), now.Add(time.Minute))

	if len(filtered.Entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(filtered.Entries))
	}
}

func TestFilterByCategory(t *testing.T) {
	tl := New()

	tl.Add(time.Now(), "test", "event1", "detail", "cat1")
	tl.Add(time.Now(), "test", "event2", "detail", "cat2")

	filtered := tl.FilterByCategory("cat1")

	if len(filtered.Entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(filtered.Entries))
	}
}

func TestCount(t *testing.T) {
	tl := New()

	tl.Add(time.Now(), "test", "event1", "detail", "cat1")
	tl.Add(time.Now(), "test", "event2", "detail", "cat1")
	tl.Add(time.Now(), "test", "event3", "detail", "cat2")

	counts := tl.Count()

	if counts["cat1"] != 2 {
		t.Errorf("Expected 2 entries in cat1, got %d", counts["cat1"])
	}
	if counts["cat2"] != 1 {
		t.Errorf("Expected 1 entry in cat2, got %d", counts["cat2"])
	}
}
