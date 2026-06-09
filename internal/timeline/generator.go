package timeline

import (
	"fmt"
	"sort"
	"time"
)

// Entry represents a timeline event.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Event     string    `json:"event"`
	Detail    string    `json:"detail,omitempty"`
	Category  string    `json:"category"`
}

// Timeline holds sorted events.
type Timeline struct {
	Entries []Entry `json:"entries"`
}

// New creates a new timeline.
func New() *Timeline {
	return &Timeline{
		Entries: []Entry{},
	}
}

// Add adds an event to the timeline.
func (t *Timeline) Add(ts time.Time, source, event, detail, category string) {
	t.Entries = append(t.Entries, Entry{
		Timestamp: ts,
		Source:    source,
		Event:     event,
		Detail:    detail,
		Category:  category,
	})
}

// Sort orders events by timestamp.
func (t *Timeline) Sort() {
	sort.Slice(t.Entries, func(i, j int) bool {
		return t.Entries[i].Timestamp.Before(t.Entries[j].Timestamp)
	})
}

// FilterByTime filters events within a time range.
func (t *Timeline) FilterByTime(start, end time.Time) *Timeline {
	result := New()
	for _, e := range t.Entries {
		if (e.Timestamp.After(start) || e.Timestamp.Equal(start)) &&
			(e.Timestamp.Before(end) || e.Timestamp.Equal(end)) {
			result.Entries = append(result.Entries, e)
		}
	}
	return result
}

// FilterByCategory filters events by category.
func (t *Timeline) FilterByCategory(category string) *Timeline {
	result := New()
	for _, e := range t.Entries {
		if e.Category == category {
			result.Entries = append(result.Entries, e)
		}
	}
	return result
}

// Count returns event counts by category.
func (t *Timeline) Count() map[string]int {
	counts := make(map[string]int)
	for _, e := range t.Entries {
		counts[e.Category]++
	}
	return counts
}

// Print displays the timeline.
func (t *Timeline) Print() {
	fmt.Println()
	fmt.Printf("  Timeline: %d events\n\n", len(t.Entries))

	if len(t.Entries) == 0 {
		fmt.Println("  No events")
		return
	}

	for _, e := range t.Entries {
		fmt.Printf("  %s [%s] %s\n", e.Timestamp.Format("2006-01-02 15:04:05"), e.Source, e.Event)
		if e.Detail != "" {
			fmt.Printf("    %s\n", e.Detail)
		}
	}
	fmt.Println()
}

// PrintSummary displays a summary of the timeline.
func (t *Timeline) PrintSummary() {
	counts := t.Count()

	fmt.Println()
	fmt.Println("  Timeline Summary")
	fmt.Println()

	if len(t.Entries) > 0 {
		fmt.Printf("  Time Range: %s to %s\n",
			t.Entries[0].Timestamp.Format("2006-01-02 15:04:05"),
			t.Entries[len(t.Entries)-1].Timestamp.Format("2006-01-02 15:04:05"))
	}

	fmt.Printf("  Total Events: %d\n\n", len(t.Entries))

	if len(counts) > 0 {
		fmt.Println("  By Category:")
		for cat, count := range counts {
			fmt.Printf("    %-30s %d\n", cat, count)
		}
	}
	fmt.Println()
}
