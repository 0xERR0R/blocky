package trie

import (
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
				Expect(sut.HasParentOf("example.com")).Should(BeFalse())
			})

			It("should not insert the empty string", func() {
				sut.Insert("")
				Expect(sut.HasParentOf("")).Should(BeFalse())
			})
		})

		When("Adding a domain", func() {
			var (
				domainOkTLD = "com"
				domainOk    = "example." + domainOkTLD

				domainKo = "example.org"
			)

			BeforeEach(func() {
				hasParent, _ := sut.HasParentOf(domainOk)
				Expect(hasParent).Should(BeFalse())
				sut.Insert(domainOk)
				hasParent, _ = sut.HasParentOf(domainOk)
				Expect(hasParent).Should(BeTrue())
			})

			AfterEach(func() {
				hasParent, _ := sut.HasParentOf(domainOk)
				Expect(hasParent).Should(BeTrue())
			})

			It("should be found", func() {})

			It("should contain subdomains", func() {
				subdomain := "www." + domainOk

				hasParent, _ := sut.HasParentOf(subdomain)
				Expect(hasParent).Should(BeTrue())
			})

			It("should support inserting subdomains", func() {
				subdomain := "www." + domainOk

				hasParent, _ := sut.HasParentOf(subdomain)
				Expect(hasParent).Should(BeTrue())
				sut.Insert(subdomain)
				hasParent, _ = sut.HasParentOf(subdomain)
				Expect(hasParent).Should(BeTrue())
			})

			It("should not find unrelated", func() {
				hasParent, _ := sut.HasParentOf(domainKo)
				Expect(hasParent).Should(BeFalse())
			})

			It("should not find uninserted parent", func() {
				hasParent, _ := sut.HasParentOf(domainOkTLD)
				Expect(hasParent).Should(BeFalse())
			})

			It("should not find deep uninserted parent", func() {
				sut.Insert("sub.sub.sub.test")

				hasParent, _ := sut.HasParentOf("sub.sub.test")
				Expect(hasParent).Should(BeFalse())
			})

			It("should find inserted parent", func() {
				sut.Insert(domainOkTLD)
				hasParent, _ := sut.HasParentOf(domainOkTLD)
				Expect(hasParent).Should(BeTrue())
			})

			It("should insert sibling", func() {
				sibling := "other." + domainOkTLD

				sut.Insert(sibling)
				hasParent, _ := sut.HasParentOf(sibling)
				Expect(hasParent).Should(BeTrue())
			})

			It("should insert grand-children siblings", func() {
				base := "other.com"
				abcSub := "abc." + base
				xyzSub := "xyz." + base

				sut.Insert(abcSub)
				hasParent, _ := sut.HasParentOf(abcSub)
				Expect(hasParent).Should(BeTrue())
				hasParent, _ = sut.HasParentOf(xyzSub)
				Expect(hasParent).Should(BeFalse())
				hasParent, _ = sut.HasParentOf(base)
				Expect(hasParent).Should(BeFalse())

				sut.Insert(xyzSub)
				hasParent, _ = sut.HasParentOf(xyzSub)
				Expect(hasParent).Should(BeTrue())
				hasParent, _ = sut.HasParentOf(abcSub)
				Expect(hasParent).Should(BeTrue())
				hasParent, _ = sut.HasParentOf(base)
				Expect(hasParent).Should(BeFalse())
			})
		})
	})
})
