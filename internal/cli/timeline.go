package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/evtx"
	"github.com/supunhg/filo-go/internal/timeline"
)

var timelineCmd = &cobra.Command{
	Use:   "timeline [files...]",
	Short: "Generate forensic timeline from multiple sources",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTimeline,
}

func runTimeline(cmd *cobra.Command, args []string) error {
	t := timeline.New()

	for _, filePath := range args {
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("  Warning: Cannot read %s: %v\n", filePath, err)
			continue
		}

		// Try EVTX parsing
		result, err := evtx.Analyze(data, filePath)
		if err == nil {
			for _, event := range result.Events {
				ts := event.TimeCreated
				if ts.IsZero() {
					ts = time.Now()
				}
				t.Add(ts, "EVTX", fmt.Sprintf("Event %d", event.EventID),
					event.Message, event.LevelName)
			}
		}
	}

	t.Sort()
	t.Print()
	t.PrintSummary()

	return nil
}
