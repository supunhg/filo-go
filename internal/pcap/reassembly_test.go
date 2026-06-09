package pcap

import (
	"testing"
)

func TestReassemblerNew(t *testing.T) {
	r := NewReassembler()
	if r == nil {
		t.Fatal("expected non-nil reassembler")
	}
	if r.streams == nil {
		t.Fatal("expected non-nil streams map")
	}
	if r.metadata == nil {
		t.Fatal("expected non-nil metadata")
	}
}

func TestProcessPacketTooSmall(t *testing.T) {
	r := NewReassembler()
	r.ProcessPacket([]byte{0x01, 0x02}, 0, 0)

	if r.metadata.TCPPackets != 0 {
		t.Error("should not process packets that are too small")
	}
}

func TestProcessPacketNotIPv4(t *testing.T) {
	r := NewReassembler()

	// Create packet with non-IPv4 EtherType (0x86DD = IPv6)
	packet := make([]byte, 60)
	packet[12] = 0x86
	packet[13] = 0xDD

	r.ProcessPacket(packet, 0, 0)

	if r.metadata.TCPPackets != 0 {
		t.Error("should not process non-IPv4 packets")
	}
}

func TestProcessTCPPacket(t *testing.T) {
	r := NewReassembler()

	// Create minimal TCP packet
	packet := make([]byte, 54) // Eth(14) + IP(20) + TCP(20)

	// Ethernet: IPv4
	packet[12] = 0x08
	packet[13] = 0x00

	// IP header
	packet[14] = 0x45 // Version 4, IHL 5
	packet[23] = 6    // Protocol: TCP

	// TCP header
	packet[34] = 0x00 // Source port (high byte)
	packet[35] = 0x50 // Source port 80
	packet[36] = 0x00 // Dest port (high byte)
	packet[37] = 0x01 // Dest port 1

	// SYN flag
	packet[47] = 0x02

	r.ProcessPacket(packet, 0, 1000)

	if r.metadata.TCPPackets != 1 {
		t.Errorf("expected 1 TCP packet, got %d", r.metadata.TCPPackets)
	}

	streams := r.Assemble()
	if len(streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(streams))
	}

	if !streams[0].Metadata.HasSYN {
		t.Error("expected SYN flag to be set")
	}
}

func TestTCPStreamID(t *testing.T) {
	id1 := StreamID{SrcIP: 1, DstIP: 2, SrcPort: 80, DstPort: 1234}
	id2 := StreamID{SrcIP: 1, DstIP: 2, SrcPort: 80, DstPort: 1234}
	id3 := StreamID{SrcIP: 1, DstIP: 2, SrcPort: 80, DstPort: 5678}

	if id1 != id2 {
		t.Error("same streams should have equal IDs")
	}
	if id1 == id3 {
		t.Error("different streams should have different IDs")
	}
}

func TestReassembleEmpty(t *testing.T) {
	r := NewReassembler()
	streams := r.Assemble()

	if len(streams) != 0 {
		t.Errorf("expected 0 streams, got %d", len(streams))
	}
}

func TestReassembleSinglePacket(t *testing.T) {
	r := NewReassembler()

	id := StreamID{SrcIP: 1, DstIP: 2, SrcPort: 80, DstPort: 1234}
	r.mu.Lock()
	r.streams[id] = &TCPStream{
		ID: id,
		Packets: []TCPPacket{
			{SeqNum: 1000, Payload: []byte("Hello, World!")},
		},
	}
	r.order = append(r.order, id)
	r.mu.Unlock()

	streams := r.Assemble()
	if len(streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(streams))
	}

	if string(streams[0].Data) != "Hello, World!" {
		t.Errorf("expected 'Hello, World!', got %q", streams[0].Data)
	}
}

func TestReassembleMultiplePackets(t *testing.T) {
	r := NewReassembler()

	id := StreamID{SrcIP: 1, DstIP: 2, SrcPort: 80, DstPort: 1234}
	r.mu.Lock()
	r.streams[id] = &TCPStream{
		ID: id,
		Packets: []TCPPacket{
			{SeqNum: 1000, Payload: []byte("Hello, ")},
			{SeqNum: 1007, Payload: []byte("World!")},
		},
	}
	r.order = append(r.order, id)
	r.mu.Unlock()

	streams := r.Assemble()
	if len(streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(streams))
	}

	if string(streams[0].Data) != "Hello, World!" {
		t.Errorf("expected 'Hello, World!', got %q", streams[0].Data)
	}
}

func TestReassembleOutOfOrder(t *testing.T) {
	r := NewReassembler()

	id := StreamID{SrcIP: 1, DstIP: 2, SrcPort: 80, DstPort: 1234}
	r.mu.Lock()
	r.streams[id] = &TCPStream{
		ID: id,
		Packets: []TCPPacket{
			{SeqNum: 1007, Payload: []byte("World!")},
			{SeqNum: 1000, Payload: []byte("Hello, ")},
		},
	}
	r.order = append(r.order, id)
	r.mu.Unlock()

	streams := r.Assemble()
	if len(streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(streams))
	}

	if string(streams[0].Data) != "Hello, World!" {
		t.Errorf("expected 'Hello, World!', got %q", streams[0].Data)
	}
}

func TestDetectProtocolHTTP(t *testing.T) {
	r := NewReassembler()

	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"GET request", []byte("GET /index.html HTTP/1.1\r\n"), "HTTP"},
		{"POST request", []byte("POST /api/data HTTP/1.1\r\n"), "HTTP"},
		{"HTTP response", []byte("HTTP/1.1 200 OK\r\n"), "HTTP"},
		{"TLS ClientHello", []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}, "TLS"},
		{"SSH", []byte("SSH-2.0-OpenSSH_8.9"), "SSH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := &TCPStream{Data: tt.data}
			result := r.detectProtocol(stream)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetStreamsByProtocol(t *testing.T) {
	r := NewReassembler()

	// Add HTTP stream
	httpID := StreamID{SrcIP: 1, DstIP: 2, SrcPort: 80, DstPort: 1234}
	r.mu.Lock()
	r.streams[httpID] = &TCPStream{
		ID:       httpID,
		Protocol: "HTTP",
	}
	r.order = append(r.order, httpID)

	// Add TLS stream
	tlsID := StreamID{SrcIP: 1, DstIP: 2, SrcPort: 443, DstPort: 1234}
	r.streams[tlsID] = &TCPStream{
		ID:       tlsID,
		Protocol: "TLS",
	}
	r.order = append(r.order, tlsID)
	r.mu.Unlock()

	httpStreams := r.GetStreamsByProtocol("HTTP")
	if len(httpStreams) != 1 {
		t.Errorf("expected 1 HTTP stream, got %d", len(httpStreams))
	}

	tlsStreams := r.GetStreamsByProtocol("TLS")
	if len(tlsStreams) != 1 {
		t.Errorf("expected 1 TLS stream, got %d", len(tlsStreams))
	}

	allStreams := r.GetStreamsByProtocol("unknown")
	if len(allStreams) != 0 {
		t.Errorf("expected 0 unknown streams, got %d", len(allStreams))
	}
}

func TestGetStream(t *testing.T) {
	r := NewReassembler()

	id := StreamID{SrcIP: 1, DstIP: 2, SrcPort: 80, DstPort: 1234}
	r.mu.Lock()
	r.streams[id] = &TCPStream{ID: id}
	r.order = append(r.order, id)
	r.mu.Unlock()

	stream, ok := r.GetStream(id)
	if !ok {
		t.Fatal("expected stream to be found")
	}
	if stream.ID != id {
		t.Error("expected matching stream ID")
	}

	_, ok = r.GetStream(StreamID{SrcIP: 3, DstIP: 4, SrcPort: 80, DstPort: 1234})
	if ok {
		t.Error("expected stream not to be found")
	}
}

func TestGetMetadata(t *testing.T) {
	r := NewReassembler()
	meta := r.GetMetadata()

	if meta == nil {
		t.Fatal("expected non-nil metadata")
	}
	if meta.TotalStreams != 0 {
		t.Errorf("expected 0 streams, got %d", meta.TotalStreams)
	}
}

func TestTCPFlags(t *testing.T) {
	if TCPFIN != 0x01 {
		t.Errorf("expected TCPFIN 0x01, got 0x%02x", TCPFIN)
	}
	if TCPSYN != 0x02 {
		t.Errorf("expected TCPSYN 0x02, got 0x%02x", TCPSYN)
	}
	if TCPRST != 0x04 {
		t.Errorf("expected TCPRST 0x04, got 0x%02x", TCPRST)
	}
	if TCPPSH != 0x08 {
		t.Errorf("expected TCPPSH 0x08, got 0x%02x", TCPPSH)
	}
	if TCPACK != 0x10 {
		t.Errorf("expected TCPACK 0x10, got 0x%02x", TCPACK)
	}
}

func TestStreamMetadata(t *testing.T) {
	m := StreamMetadata{
		PacketCount: 100,
		TotalBytes:  50000,
		HasFIN:      true,
		HasSYN:      true,
		HasRST:      false,
	}

	if m.PacketCount != 100 {
		t.Errorf("expected 100 packets, got %d", m.PacketCount)
	}
	if m.TotalBytes != 50000 {
		t.Errorf("expected 50000 bytes, got %d", m.TotalBytes)
	}
	if !m.HasFIN {
		t.Error("expected FIN to be set")
	}
	if !m.HasSYN {
		t.Error("expected SYN to be set")
	}
	if m.HasRST {
		t.Error("expected RST not to be set")
	}
}
