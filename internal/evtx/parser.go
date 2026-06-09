package evtx

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Result holds EVTX analysis results.
type Result struct {
	FileName    string         `json:"file_name"`
	TotalEvents int            `json:"total_events"`
	Events      []Event        `json:"events"`
	Stats       map[string]int `json:"stats"`
	Flags       []string       `json:"flags,omitempty"`
}

// Event represents a single Windows Event Log entry.
type Event struct {
	TimeCreated time.Time `json:"time_created"`
	EventID     uint16    `json:"event_id"`
	Level       uint8     `json:"level"`
	Provider    string    `json:"provider"`
	Computer    string    `json:"computer"`
	Message     string    `json:"message"`
	Channel     string    `json:"channel"`
	LevelName   string    `json:"level_name"`
}

var suspiciousEventIDs = map[uint16]string{
	4624: "Successful logon",
	4625: "Failed logon",
	4648: "Explicit credentials logon",
	4672: "Special privileges assigned",
	4688: "New process created",
	4697: "Service installed",
	4698: "Scheduled task created",
	4699: "Scheduled task deleted",
	4720: "User account created",
	4722: "User account enabled",
	4724: "Password reset attempt",
	4728: "Member added to security-enabled global group",
	4732: "Member added to security-enabled local group",
	4756: "Member added to security-enabled universal group",
	4768: "Kerberos TGT requested",
	4769: "Kerberos service ticket requested",
	4771: "Kerberos pre-authentication failed",
	4776: "NTLM authentication",
	5140: "Network share accessed",
	5156: "Windows Filtering Platform allowed connection",
}

// Analyze parses EVTX file data.
func Analyze(data []byte, fileName string) (*Result, error) {
	result := &Result{
		FileName: fileName,
		Stats:    make(map[string]int),
	}

	if len(data) < 4096 {
		return result, fmt.Errorf("file too small for EVTX")
	}

	// Check EVTX signature
	signature := string(data[:8])
	if signature != "ElfFile\x00" {
		return result, fmt.Errorf("not a valid EVTX file")
	}

	// Parse chunks
	offset := 4096 // Skip header
	chunkCount := 0

	for offset+512 <= len(data) {
		// Check chunk signature
		if string(data[offset:offset+8]) != "ElfChnk\x00" {
			break
		}

		chunkSize := int(binary.LittleEndian.Uint32(data[offset+24 : offset+28]))
		if chunkSize <= 0 || offset+chunkSize > len(data) {
			break
		}

		// Parse events in chunk
		events := parseChunk(data[offset : offset+chunkSize])
		result.Events = append(result.Events, events...)
		result.TotalEvents += len(events)

		offset += chunkSize
		chunkCount++
	}

	// Calculate stats
	for _, event := range result.Events {
		result.Stats[event.Provider]++
		result.Stats[event.LevelName]++
	}

	// Detect suspicious events
	for _, event := range result.Events {
		if msg, ok := suspiciousEventIDs[event.EventID]; ok {
			if event.EventID == 4625 || event.EventID == 4648 || event.EventID == 4697 || event.EventID == 4698 {
				result.Flags = append(result.Flags, fmt.Sprintf("Event %d: %s at %s", event.EventID, msg, event.TimeCreated.Format(time.RFC3339)))
			}
		}
	}

	return result, nil
}

func parseChunk(data []byte) []Event {
	var events []Event

	// Simplified chunk parsing
	// In production, this would parse the full EVTX chunk structure
	offset := 128 // Skip chunk header

	for offset+24 <= len(data) {
		// Look for event records
		if data[offset] == 0x2A && data[offset+1] == 0x00 {
			// Found an event record
			if offset+24 < len(data) {
				event := Event{
					EventID:   binary.LittleEndian.Uint16(data[offset+4 : offset+6]),
					Level:     data[offset+8],
					LevelName: levelName(data[offset+8]),
				}
				events = append(events, event)
			}
		}
		offset += 8
	}

	return events
}

func levelName(level uint8) string {
	switch level {
	case 0:
		return "LogAlways"
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Information"
	case 5:
		return "Verbose"
	default:
		return "Unknown"
	}
}

// Print displays EVTX results.
func Print(r *Result) {
	fmt.Println()
	fmt.Printf("  Windows Event Log: %s\n", r.FileName)
	fmt.Printf("  Total Events: %d\n", r.TotalEvents)
	fmt.Println()

	if len(r.Flags) > 0 {
		fmt.Println("  ⚠  Suspicious Events:")
		for _, f := range r.Flags {
			fmt.Printf("    %s\n", f)
		}
		fmt.Println()
	}

	if len(r.Stats) > 0 {
		fmt.Println("  Statistics:")
		for k, v := range r.Stats {
			if v > 0 && !strings.Contains(k, "\x00") {
				fmt.Printf("    %-30s %d\n", k, v)
			}
		}
	}
	fmt.Println()
}
