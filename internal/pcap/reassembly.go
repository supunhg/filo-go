package pcap

import (
	"encoding/binary"
	"sort"
	"sync"
)

// TCPStream represents a reassembled TCP stream.
type TCPStream struct {
	ID        StreamID
	Packets   []TCPPacket
	Data      []byte // Reassembled payload
	Protocol  string // Detected protocol (HTTP, DNS, etc.)
	Metadata  StreamMetadata
}

// StreamID uniquely identifies a TCP stream.
type StreamID struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
}

// TCPPacket is a single TCP packet with metadata.
type TCPPacket struct {
	SeqNum   uint32
	AckNum   uint32
	Flags    uint8
	Offset   int    // Offset in original capture
	Payload  []byte
	Timestamp uint32
}

// StreamMetadata holds analysis results for a stream.
type StreamMetadata struct {
	PacketCount   int
	TotalBytes    int
	HasFIN        bool
	HasSYN        bool
	HasRST        bool
	Direction     string // "client->server" or "server->client"
	Application   string // Detected application protocol
}

const (
	TCPFIN = 0x01
	TCPSYN = 0x02
	TCPRST = 0x04
	TCPPSH = 0x08
	TCPACK = 0x10
)

// Reassembler handles TCP stream reassembly.
type Reassembler struct {
	mu       sync.Mutex
	streams  map[StreamID]*TCPStream
	order    []StreamID
	metadata *ReassemblyMetadata
}

// ReassemblyMetadata holds global reassembly stats.
type ReassemblyMetadata struct {
	TotalStreams   int
	TCPPackets     int
	UDPPackets     int
	ICMPPackets    int
	ARPackets      int
	TotalBytes     int
}

// NewReassembler creates a new TCP reassembler.
func NewReassembler() *Reassembler {
	return &Reassembler{
		streams: make(map[StreamID]*TCPStream),
		metadata: &ReassemblyMetadata{},
	}
}

// ProcessPacket adds a packet to the reassembler.
func (r *Reassembler) ProcessPacket(data []byte, offset int, timestamp uint32) {
	if len(data) < 42 { // Minimum: Eth(14) + IP(20) + TCP(8)
		return
	}

	// Parse Ethernet
	etherType := binary.BigEndian.Uint16(data[12:14])
	if etherType != 0x0800 { // Not IPv4
		if etherType == 0x0806 {
			r.metadata.ARPackets++
		}
		return
	}

	// Parse IP
	ipHeader := data[14:]
	if len(ipHeader) < 20 {
		return
	}

	version := ipHeader[0] >> 4
	if version != 4 {
		return // Skip IPv6 for now
	}

	totalLen := binary.BigEndian.Uint16(ipHeader[2:4])
	protocol := ipHeader[9]
	srcIP := binary.BigEndian.Uint32(ipHeader[12:16])
	dstIP := binary.BigEndian.Uint32(ipHeader[16:20])

	switch protocol {
	case 6: // TCP
		r.metadata.TCPPackets++
		r.processTCP(ipHeader, srcIP, dstIP, offset, timestamp, int(totalLen))
	case 17: // UDP
		r.metadata.UDPPackets++
	case 1: // ICMP
		r.metadata.ICMPPackets++
	}
}

func (r *Reassembler) processTCP(ipHeader []byte, srcIP, dstIP uint32, offset int, timestamp uint32, totalLen int) {
	if len(ipHeader) < 40 {
		return
	}

	tcpHeader := ipHeader[20:]
	srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(tcpHeader[2:4])
	seqNum := binary.BigEndian.Uint32(tcpHeader[4:8])
	ackNum := binary.BigEndian.Uint32(tcpHeader[8:12])
	flags := tcpHeader[13]
	dataOffset := int(tcpHeader[12]>>4) * 4

	if len(tcpHeader) < dataOffset {
		return
	}

	payload := tcpHeader[dataOffset:]

	// Create stream ID (normalize to client->server)
	id := StreamID{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Get or create stream
	stream, exists := r.streams[id]
	if !exists {
		stream = &TCPStream{
			ID:      id,
			Metadata: StreamMetadata{},
		}
		r.streams[id] = stream
		r.order = append(r.order, id)
	}

	// Track flags
	stream.Metadata.PacketCount++
	if flags&TCPFIN != 0 {
		stream.Metadata.HasFIN = true
	}
	if flags&TCPSYN != 0 {
		stream.Metadata.HasSYN = true
	}
	if flags&TCPRST != 0 {
		stream.Metadata.HasRST = true
	}

	// Add packet
	stream.Packets = append(stream.Packets, TCPPacket{
		SeqNum:    seqNum,
		AckNum:    ackNum,
		Flags:     flags,
		Offset:    offset,
		Payload:   payload,
		Timestamp: timestamp,
	})

	stream.Metadata.TotalBytes += len(payload)
}

// Assemble performs TCP stream reassembly.
func (r *Reassembler) Assemble() []*TCPStream {
	r.mu.Lock()
	defer r.mu.Unlock()

	var streams []*TCPStream

	for _, id := range r.order {
		stream := r.streams[id]

		// Sort packets by sequence number
		sort.Slice(stream.Packets, func(i, j int) bool {
			return stream.Packets[i].SeqNum < stream.Packets[j].SeqNum
		})

		// Reassemble payload
		stream.Data = r.reassemblePayload(stream.Packets)

		// Detect application protocol
		stream.Protocol = r.detectProtocol(stream)

		streams = append(streams, stream)
	}

	r.metadata.TotalStreams = len(streams)
	return streams
}

func (r *Reassembler) reassemblePayload(packets []TCPPacket) []byte {
	if len(packets) == 0 {
		return nil
	}

	// Find starting sequence number
	minSeq := packets[0].SeqNum
	for _, p := range packets[1:] {
		if p.SeqNum < minSeq {
			minSeq = p.SeqNum
		}
	}

	// Build payload map
	payloadMap := make(map[uint32][]byte)
	for _, p := range packets {
		if len(p.Payload) > 0 {
			offset := p.SeqNum - minSeq
			payloadMap[offset] = p.Payload
		}
	}

	// Sort offsets
	var offsets []uint32
	for offset := range payloadMap {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool {
		return offsets[i] < offsets[j]
	})

	// Concatenate payloads
	var result []byte
	for _, offset := range offsets {
		result = append(result, payloadMap[offset]...)
	}

	return result
}

func (r *Reassembler) detectProtocol(stream *TCPStream) string {
	if len(stream.Data) < 10 {
		return "unknown"
	}

	// Check for HTTP
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}
	data := string(stream.Data[:min(20, len(stream.Data))])
	for _, method := range httpMethods {
		if len(data) >= len(method) && data[:len(method)] == method {
			return "HTTP"
		}
	}

	// Check for HTTP response
	if len(data) >= 4 && data[:4] == "HTTP" {
		return "HTTP"
	}

	// Check for TLS ClientHello
	if stream.Data[0] == 0x16 && stream.Data[1] == 0x03 {
		return "TLS"
	}

	// Check for DNS over TCP (length prefix)
	if len(stream.Data) >= 2 {
		dnsLen := binary.BigEndian.Uint16(stream.Data[0:2])
		if int(dnsLen) == len(stream.Data)-2 {
			return "DNS"
		}
	}

	// Check for SSH
	if len(stream.Data) >= 4 && string(stream.Data[:4]) == "SSH-" {
		return "SSH"
	}

	// Check for SMTP
	smtpPrefixes := []string{"220 ", "EHLO ", "MAIL FROM:"}
	for _, prefix := range smtpPrefixes {
		if len(data) >= len(prefix) && data[:len(prefix)] == prefix {
			return "SMTP"
		}
	}

	// Check for FTP
	ftpPrefixes := []string{"220 ", "USER ", "PASS ", "QUIT"}
	for _, prefix := range ftpPrefixes {
		if len(data) >= len(prefix) && data[:len(prefix)] == prefix {
			return "FTP"
		}
	}

	return "unknown"
}

// GetStream returns a specific stream by ID.
func (r *Reassembler) GetStream(id StreamID) (*TCPStream, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stream, ok := r.streams[id]
	return stream, ok
}

// GetStreamsByProtocol returns streams matching a protocol.
func (r *Reassembler) GetStreamsByProtocol(protocol string) []*TCPStream {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []*TCPStream
	for _, id := range r.order {
		stream := r.streams[id]
		if stream.Protocol == protocol {
			result = append(result, stream)
		}
	}
	return result
}

// GetMetadata returns reassembly statistics.
func (r *Reassembler) GetMetadata() *ReassemblyMetadata {
	return r.metadata
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
