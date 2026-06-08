package trie

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Trie", func() {
	var sut *Trie

	BeforeEach(func() {
		sut = NewTrie(SplitTLD)
	})

	Describe("Basic operations", func() {
		When("Trie is created", func() {
			It("should be empty", func() {
				Expect(sut.IsEmpty()).Should(BeTrue())
			})

			It("should not find domains", func() {
				_, ok := sut.HasParentOf("example.com")
				Expect(ok).Should(BeFalse())
			})

			It("should not insert the empty string", func() {
				sut.Insert("")
				_, ok := sut.HasParentOf("")
				Expect(ok).Should(BeFalse())
			})
		})

		When("Adding a domain", func() {
			var (
				domainOkTLD = "com"
				domainOk    = "example." + domainOkTLD

				domainKo = "example.org"
			)

			BeforeEach(func() {
				_, ok := sut.HasParentOf(domainOk)
				Expect(ok).Should(BeFalse())
				sut.Insert(domainOk)
				_, ok = sut.HasParentOf(domainOk)
				Expect(ok).Should(BeTrue())
			})

			AfterEach(func() {
				_, ok := sut.HasParentOf(domainOk)
				Expect(ok).Should(BeTrue())
			})

			It("should be found", func() {})

			It("should contain subdomains", func() {
				subdomain := "www." + domainOk

				_, ok := sut.HasParentOf(subdomain)
				Expect(ok).Should(BeTrue())
			})

			It("should support inserting subdomains", func() {
				subdomain := "www." + domainOk

				_, ok := sut.HasParentOf(subdomain)
				Expect(ok).Should(BeTrue())
				sut.Insert(subdomain)
				_, ok = sut.HasParentOf(subdomain)
				Expect(ok).Should(BeTrue())
			})

			It("should not find unrelated", func() {
				_, ok := sut.HasParentOf(domainKo)
				Expect(ok).Should(BeFalse())
			})

			It("should not find uninserted parent", func() {
				_, ok := sut.HasParentOf(domainOkTLD)
				Expect(ok).Should(BeFalse())
			})

			It("should not find deep uninserted parent", func() {
				sut.Insert("sub.sub.sub.test")

				_, ok := sut.HasParentOf("sub.sub.test")
				Expect(ok).Should(BeFalse())
			})

			It("should find inserted parent", func() {
				sut.Insert(domainOkTLD)
				_, ok := sut.HasParentOf(domainOkTLD)
				Expect(ok).Should(BeTrue())
			})

			It("should insert sibling", func() {
				sibling := "other." + domainOkTLD

				sut.Insert(sibling)
				_, ok := sut.HasParentOf(sibling)
				Expect(ok).Should(BeTrue())
			})

			It("should insert grand-children siblings", func() {
				base := "other.com"
				abcSub := "abc." + base
				xyzSub := "xyz." + base

				sut.Insert(abcSub)
				_, ok := sut.HasParentOf(abcSub)
				Expect(ok).Should(BeTrue())
				_, ok = sut.HasParentOf(xyzSub)
				Expect(ok).Should(BeFalse())
				_, ok = sut.HasParentOf(base)
				Expect(ok).Should(BeFalse())

				sut.Insert(xyzSub)
				_, ok = sut.HasParentOf(xyzSub)
				Expect(ok).Should(BeTrue())
				_, ok = sut.HasParentOf(abcSub)
				Expect(ok).Should(BeTrue())
				_, ok = sut.HasParentOf(base)
				Expect(ok).Should(BeFalse())
			})
		})
	})

	Describe("Matched entry reconstruction", func() {
		// HasParentOf returns the labels of the matched stored entry; joining
		// them with the domain separator must reproduce the original entry.
		reconstruct := func(labels []string) string {
			return strings.Join(labels, ".")
		}

		It("reconstructs a single-label-prefix entry from a subdomain match", func() {
			sut.Insert("example.com")

			labels, ok := sut.HasParentOf("www.example.com")
			Expect(ok).Should(BeTrue())
			Expect(reconstruct(labels)).Should(Equal("example.com"))
		})

		It("reconstructs the entry on an exact match", func() {
			sut.Insert("example.com")

			labels, ok := sut.HasParentOf("example.com")
			Expect(ok).Should(BeTrue())
			Expect(reconstruct(labels)).Should(Equal("example.com"))
		})

		It("reconstructs a multi-label entry", func() {
			sut.Insert("sub.example.com")

			labels, ok := sut.HasParentOf("a.sub.example.com")
			Expect(ok).Should(BeTrue())
			Expect(reconstruct(labels)).Should(Equal("sub.example.com"))
		})

		It("reconstructs the matched sibling under a shared parent node", func() {
			sut.Insert("a.com")
			sut.Insert("b.com")

			labels, ok := sut.HasParentOf("x.a.com")
			Expect(ok).Should(BeTrue())
			Expect(reconstruct(labels)).Should(Equal("a.com"))
		})

		It("returns nil labels when there is no match", func() {
			sut.Insert("example.com")

			labels, ok := sut.HasParentOf("example.org")
			Expect(ok).Should(BeFalse())
			Expect(labels).Should(BeNil())
		})
	})
})
