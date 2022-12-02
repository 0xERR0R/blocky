package stringcache

import (
	"math/rand"
	"testing"
)

func BenchmarkStringCache(b *testing.B) {
	testdata := createTestdata(10_000)

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		factory := newStringCacheFactory()

		for _, s := range testdata {
			factory.AddEntry(s)
		}

		factory.Create()
	}
}

func randString(n int) string {
	const charPool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-."

	b := make([]byte, n)

	for i := range b {
		b[i] = charPool[rand.Intn(len(charPool))]
	}

	return string(b)
}

func createTestdata(count int) []string {
	var result []string

	for i := 0; i < count; i++ {
		result = append(result, randString(8+rand.Intn(20)))
	}

	return result
}
