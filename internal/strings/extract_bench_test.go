package strings

import (
	"os"
	"testing"
)

func BenchmarkExtract10MB(b *testing.B) {
	data, err := os.ReadFile("/tmp/bench-corpus/random-10mb.bin")
	if err != nil { b.Fatal(err) }
	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_, _ = Extract(data, "random-10mb.bin", &Options{MinLength: 4, Type: "ascii"})
	}
}
