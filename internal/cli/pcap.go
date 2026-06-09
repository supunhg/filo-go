package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/pcap"
)

var (
	pcapExtract bool
	pcapStreams  bool
	pcapProto   string
)

var pcapCmd = &cobra.Command{
	Use:   "pcap [file]",
	Short: "Analyze PCAP network capture files",
	Long: `Analyze PCAP files to extract network flows, protocols, and files.

Examples:
  filo analyze capture.pcap           # Basic analysis
  filo pcap capture.pcap --streams    # Show TCP streams
  filo pcap capture.pcap --extract    # Extract files
  filo pcap capture.pcap --proto tcp  # Filter by protocol`,
	Args: cobra.ExactArgs(1),
	RunE: runPCAP,
}

func init() {
	pcapCmd.Flags().BoolVar(&pcapExtract, "extract", false, "Extract files from capture")
	pcapCmd.Flags().BoolVar(&pcapStreams, "streams", false, "Show TCP streams")
	pcapCmd.Flags().StringVar(&pcapProto, "proto", "", "Filter by protocol (tcp, udp, http)")
	rootCmd.AddCommand(pcapCmd)
}

func runPCAP(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	// Basic analysis
	result, err := pcap.Analyze(data, filePath)
	if err != nil {
		return fmt.Errorf("PCAP analysis failed: %w", err)
	}

	// Print basic results
	printPCAPResult(result)

	// TCP reassembly if requested
	if pcapStreams || pcapProto != "" {
		fmt.Println("\n  TCP Stream Analysis")
		fmt.Println("  ===================")
		fmt.Println()

		reassembler := pcap.NewReassembler()

		// Process packets for reassembly
		offset := 24 // Skip global header
		for offset+16 <= len(data) {
			// Read packet header
			tsSec := uint32(data[offset]) | uint32(data[offset+1])<<8 |
				uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
			inclLen := uint32(data[offset+8]) | uint32(data[offset+9])<<8 |
				uint32(data[offset+10])<<16 | uint32(data[offset+11])<<24

			offset += 16

			if offset+int(inclLen) > len(data) {
				break
			}

			packet := data[offset : offset+int(inclLen)]
			reassembler.ProcessPacket(packet, offset, tsSec)
			offset += int(inclLen)
		}

		// Assemble streams
		streams := reassembler.Assemble()

		// Filter by protocol if specified
		if pcapProto != "" {
			var filtered []*pcap.TCPStream
			for _, s := range streams {
				if s.Protocol == pcapProto {
					filtered = append(filtered, s)
				}
			}
			streams = filtered
		}

		// Print streams
		fmt.Printf("  Found %d TCP stream(s)", len(streams))
		fmt.Println()
		fmt.Println()

		for i, stream := range streams {
			if i >= 20 {
				fmt.Printf("  ... and %d more streams", len(streams)-20)
				fmt.Println()
				break
			}

			fmt.Printf("  Stream %d: %s", i+1, stream.Protocol)
			fmt.Println()
			fmt.Printf("    Packets: %d", stream.Metadata.PacketCount)
			fmt.Println()
			fmt.Printf("    Bytes: %d", stream.Metadata.TotalBytes)
			fmt.Println()
			if stream.Metadata.HasSYN {
				fmt.Println("    SYN: Yes")
			}
			if stream.Metadata.HasFIN {
				fmt.Println("    FIN: Yes")
			}

			// Show first 100 bytes of payload
			if len(stream.Data) > 0 {
				preview := stream.Data
				if len(preview) > 100 {
					preview = preview[:100]
				}
				fmt.Printf("    Payload preview: %s", string(preview))
				fmt.Println()
			}
			fmt.Println()
		}

		// Extract files if requested
		if pcapExtract {
			fmt.Println("\n  File Extraction")
			fmt.Println("  ===============")
			fmt.Println()

			extracted := 0
			for _, stream := range streams {
				if stream.Protocol == "HTTP" && len(stream.Data) > 0 {
					// Try to extract HTTP body
					bodyStart := findHTTPBody(stream.Data)
					if bodyStart > 0 && bodyStart < len(stream.Data) {
						body := stream.Data[bodyStart:]
						if len(body) > 0 {
							outPath := fmt.Sprintf("extracted_%d.bin", extracted)
							if err := os.WriteFile(outPath, body, 0644); err == nil {
								fmt.Printf("  Extracted: %s (%d bytes)", outPath, len(body))
								fmt.Println()
								extracted++
							}
						}
					}
				}
			}

			if extracted == 0 {
				fmt.Println("  No files extracted")
			}
		}
	}

	fmt.Println()
	return nil
}

func printPCAPResult(result *pcap.Result) {
	fmt.Println()
	fmt.Printf("  PCAP Analysis: %s", result.FileName)
	fmt.Println()
	fmt.Printf("  Packets: %d", result.PacketCount)
	fmt.Println()
	fmt.Println()

	if len(result.Protocols) > 0 {
		fmt.Println("  Protocols:")
		for proto, count := range result.Protocols {
			fmt.Printf("    %-10s %d", proto, count)
			fmt.Println()
		}
		fmt.Println()
	}

	if len(result.HTTPRequests) > 0 {
		fmt.Println("  HTTP Requests:")
		for _, req := range result.HTTPRequests {
			fmt.Printf("    %s %s %s", req.Method, req.Host, req.Path)
			fmt.Println()
		}
		fmt.Println()
	}

	if len(result.Flags) > 0 {
		fmt.Println("  Flags Found:")
		for _, flag := range result.Flags {
			fmt.Printf("    %s", flag)
			fmt.Println()
		}
		fmt.Println()
	}
}

func findHTTPBody(data []byte) int {
	// Find the end of HTTP headers
	for i := 0; i < len(data)-4; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return i + 4
		}
	}
	return -1
}
