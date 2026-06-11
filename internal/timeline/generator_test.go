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

func TestPrint(t *testing.T) {
	tl := New()

	// Test empty timeline
	tl.Print()

	// Test with events
	tl.Add(time.Now(), "test", "event1", "detail", "cat1")
	tl.Add(time.Now(), "test", "event2", "", "cat2")

	tl.Print()
}

func TestPrintSummary(t *testing.T) {
	tl := New()

	// Test empty timeline
	tl.PrintSummary()

	// Test with events
	tl.Add(time.Now(), "test", "event1", "detail", "cat1")
	tl.Add(time.Now(), "test", "event2", "detail", "cat1")
	tl.Add(time.Now(), "test", "event3", "detail", "cat2")

	tl.PrintSummary()
}

func TestAddMultipleEvents(t *testing.T) {
	tl := New()

	for i := 0; i < 10; i++ {
		tl.Add(time.Now().Add(time.Duration(i)*time.Second), "test", "event", "detail", "cat")
	}

	if len(tl.Entries) != 10 {
		t.Errorf("Expected 10 entries, got %d", len(tl.Entries))
	}
}

func TestSortMultipleEvents(t *testing.T) {
	tl := New()

	// Add events in reverse order
	for i := 9; i >= 0; i-- {
		tl.Add(time.Now().Add(time.Duration(i)*time.Second), "test", "event", "detail", "cat")
	}

	tl.Sort()

	// Verify sorted order
	for i := 1; i < len(tl.Entries); i++ {
		if tl.Entries[i].Timestamp.Before(tl.Entries[i-1].Timestamp) {
			t.Errorf("Events not sorted correctly at index %d", i)
		}
	}
}

func TestFilterByTimeEdgeCases(t *testing.T) {
	tl := New()

	now := time.Now()
	tl.Add(now, "test", "event1", "detail", "cat")
	tl.Add(now.Add(time.Hour), "test", "event2", "detail", "cat")

	// Filter with exact start time
	filtered := tl.FilterByTime(now, now.Add(time.Hour))
	if len(filtered.Entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(filtered.Entries))
	}

	// Filter with exact end time
	filtered = tl.FilterByTime(now, now.Add(time.Hour))
	if len(filtered.Entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(filtered.Entries))
	}

	// Filter with no matches
	filtered = tl.FilterByTime(now.Add(2*time.Hour), now.Add(3*time.Hour))
	if len(filtered.Entries) != 0 {
		t.Errorf("Expected 0 entries, got %d", len(filtered.Entries))
	}
}

func TestFilterByCategoryEdgeCases(t *testing.T) {
	tl := New()

	tl.Add(time.Now(), "test", "event1", "detail", "cat1")
	tl.Add(time.Now(), "test", "event2", "detail", "cat2")

	// Filter with non-existent category
	filtered := tl.FilterByCategory("nonexistent")
	if len(filtered.Entries) != 0 {
		t.Errorf("Expected 0 entries, got %d", len(filtered.Entries))
	}

	// Filter with empty category
	filtered = tl.FilterByCategory("")
	if len(filtered.Entries) != 0 {
		t.Errorf("Expected 0 entries, got %d", len(filtered.Entries))
	}
}

func TestCountEmpty(t *testing.T) {
	tl := New()

	counts := tl.Count()

	if len(counts) != 0 {
		t.Errorf("Expected 0 categories, got %d", len(counts))
	}
}

func TestEntryStructure(t *testing.T) {
	now := time.Now()
	entry := Entry{
		Timestamp: now,
		Source:    "test_source",
		Event:     "test_event",
		Detail:    "test_detail",
		Category:  "test_category",
	}

	if entry.Timestamp != now {
		t.Error("Timestamp mismatch")
	}
	if entry.Source != "test_source" {
		t.Error("Source mismatch")
	}
	if entry.Event != "test_event" {
		t.Error("Event mismatch")
	}
	if entry.Detail != "test_detail" {
		t.Error("Detail mismatch")
	}
	if entry.Category != "test_category" {
		t.Error("Category mismatch")
	}
}
