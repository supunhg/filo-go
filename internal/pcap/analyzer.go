package pcap

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// Result holds PCAP analysis results.
type Result struct {
	FileName           string         `json:"file_name"`
	PacketCount        int            `json:"packet_count"`
	Protocols          map[string]int `json:"protocols"`
	Flags              []string       `json:"flags,omitempty"`
	HTTPRequests       []HTTPRequest  `json:"http_requests,omitempty"`
	Base64Data         []string       `json:"base64_data,omitempty"`
	InterestingStrings []string       `json:"interesting_strings,omitempty"`
}

// HTTPRequest represents an extracted HTTP request.
type HTTPRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Host   string `json:"host"`
}

// Analyze performs PCAP analysis.
func Analyze(data []byte, fileName string) (*Result, error) {
	result := &Result{
		FileName:  fileName,
		Protocols: make(map[string]int),
	}

	if len(data) < 24 {
		return result, fmt.Errorf("file too small for PCAP")
	}

	// Parse PCAP global header
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 {
		return result, fmt.Errorf("not a valid PCAP file")
	}

	littleEndian := magic == 0xa1b2c3d4

	// Parse packets
	offset := 24 // Skip global header
	for offset+16 <= len(data) {
		// Packet header
		var tsSec, tsLen uint32
		if littleEndian {
			tsSec = binary.LittleEndian.Uint32(data[offset : offset+4])
			tsLen = binary.LittleEndian.Uint32(data[offset+12 : offset+16])
		} else {
			tsSec = binary.BigEndian.Uint32(data[offset : offset+4])
			tsLen = binary.BigEndian.Uint32(data[offset+12 : offset+16])
		}

		offset += 16

		if offset+int(tsLen) > len(data) {
			break
		}

		packet := data[offset : offset+int(tsLen)]
		offset += int(tsLen)

		result.PacketCount++
		_ = tsSec

		// Analyze packet
		analyzePacket(packet, result)
	}

	// Search for flags in all extracted data
	searchForFlags(result)

	return result, nil
}

func analyzePacket(packet []byte, r *Result) {
	if len(packet) < 14 {
		return
	}

	// Ethernet header
	etherType := binary.BigEndian.Uint32(append([]byte{0, 0}, packet[12:14]...))
	_ = etherType

	// Check for IP
	if len(packet) >= 34 {
		ipHeader := packet[14:]
		protocol := ipHeader[9]

		switch protocol {
		case 1:
			r.Protocols["ICMP"]++
		case 6:
			r.Protocols["TCP"]++
			if len(ipHeader) >= 34 {
				tcpHeader := ipHeader[20:]
				srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
				dstPort := binary.BigEndian.Uint16(tcpHeader[2:4])

				if srcPort == 80 || dstPort == 80 || srcPort == 443 || dstPort == 443 {
					r.Protocols["HTTP"]++
					extractHTTP(tcpHeader[20:], r)
				}
			}
		case 17:
			r.Protocols["UDP"]++
			if len(ipHeader) >= 28 {
				udpHeader := ipHeader[20:]
				srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
				dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
				if srcPort == 53 || dstPort == 53 {
					r.Protocols["DNS"]++
				}
			}
		}

		// Extract strings from payload
		payload := ipHeader[20:]
		extractStrings(payload, r)
	}

	// Check for ARP
	if len(packet) >= 28 && packet[12] == 0x08 && packet[13] == 0x06 {
		r.Protocols["ARP"]++
	}
}

func extractHTTP(data []byte, r *Result) {
	if len(data) < 10 {
		return
	}

	text := string(data)
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}

	for _, method := range methods {
		if strings.HasPrefix(text, method) {
			lines := strings.Split(text, "\r\n")
			if len(lines) > 0 {
				parts := strings.SplitN(lines[0], " ", 3)
				path := "/"
				if len(parts) > 1 {
					path = parts[1]
				}

				host := ""
				for _, line := range lines[1:] {
					if strings.HasPrefix(line, "Host:") {
						host = strings.TrimPrefix(line, "Host:")
						host = strings.TrimSpace(host)
						break
					}
				}

				r.HTTPRequests = append(r.HTTPRequests, HTTPRequest{
					Method: method,
					Path:   path,
					Host:   host,
				})
			}
			break
		}
	}
}

func extractStrings(data []byte, r *Result) {
	var current []byte
	for _, b := range data {
		if b >= 0x20 && b <= 0x7E {
			current = append(current, b)
		} else {
			if len(current) >= 8 {
				str := string(current)
				// Filter out common noise
				if !strings.Contains(str, "Content-") &&
					!strings.Contains(str, "HTTP/1.") &&
					len(str) > 8 {
					r.InterestingStrings = append(r.InterestingStrings, str)
				}
			}
			current = nil
		}
	}
}

func searchForFlags(r *Result) {
	patterns := []string{
		`picoCTF\{[^}]+\}`,
		`flag\{[^}]+\}`,
		`FLAG\{[^}]+\}`,
		`HTB\{[^}]+\}`,
		`CTF\{[^}]+\}`,
	}

	allText := strings.Join(r.InterestingStrings, " ")

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		matches := re.FindAllString(allText, -1)
		for _, m := range matches {
			r.Flags = append(r.Flags, m)
		}
	}
}
