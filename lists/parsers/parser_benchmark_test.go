package parsers

import (
	"bytes"
	"context"
	"os"
	"testing"
)

// BenchmarkHostsParse measures parsing the real oisd denylist (~680k entries)
// through the full Hosts parser, including per-entry iteration. It reports
// allocations, which dominate the parse cost.
func BenchmarkHostsParse(b *testing.B) {
	data, err := os.ReadFile("../../helpertest/data/oisd-big-plain.txt")
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		p := AllowErrors(Hosts(bytes.NewReader(data)), NoErrorLimit)
		p.OnErr(func(error) {})

		err := ForEach[*HostsIterator](ctx, p, func(entry *HostsIterator) error {
			return entry.ForEach(func(string) error { return nil })
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
