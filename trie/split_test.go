package trie

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SpltTLD", func() {
	It("should split a tld", func() {
		key, rest := SplitTLD("www.example.com")
		Expect(key).Should(Equal("com"))
		Expect(rest).Should(Equal("www.example"))
	})

	It("should not split a plain string", func() {
		key, rest := SplitTLD("example")
		Expect(key).Should(Equal("example"))
		Expect(rest).Should(Equal(""))
	})

	It("should not crash with an empty string", func() {
		key, rest := SplitTLD("")
		Expect(key).Should(Equal(""))
		Expect(rest).Should(Equal(""))
	})

	It("should ignore trailing dots", func() {
		key, rest := SplitTLD("www.example.com.")
		Expect(key).Should(Equal("com"))
		Expect(rest).Should(Equal("www.example"))

		key, rest = SplitTLD(rest)
		Expect(key).Should(Equal("example"))
		Expect(rest).Should(Equal("www"))
	})

	It("should skip empty parts", func() {
		key, rest := SplitTLD("www.example..com")
		Expect(key).Should(Equal("com"))
		Expect(rest).Should(Equal("www.example."))

		key, rest = SplitTLD(rest)
		Expect(key).Should(Equal("example"))
		Expect(rest).Should(Equal("www"))
	})
})

var _ = Describe("JoinTLD", func() {
	It("reconstructs an entry from labels in entry order", func() {
		Expect(JoinTLD([]string{"example", "com"})).Should(Equal("example.com"))
	})

	It("handles a single label", func() {
		Expect(JoinTLD([]string{"blocked"})).Should(Equal("blocked"))
	})

	It("reproduces the labels returned by HasParentOf", func() {
		sut := NewTrie(SplitTLD)
		sut.Insert("sub.example.com")

		labels, ok := sut.HasParentOf("a.sub.example.com")
		Expect(ok).Should(BeTrue())
		Expect(JoinTLD(labels)).Should(Equal("sub.example.com"))
	})
})
