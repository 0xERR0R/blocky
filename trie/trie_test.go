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
				Expect(sut.HasParentOf(domainOk)).Should(BeFalse())
				sut.Insert(domainOk)
				Expect(sut.HasParentOf(domainOk)).Should(BeTrue())
			})

			AfterEach(func() {
				Expect(sut.HasParentOf(domainOk)).Should(BeTrue())
			})

			It("should be found", func() {})

			It("should contain subdomains", func() {
				subdomain := "www." + domainOk

				Expect(sut.HasParentOf(subdomain)).Should(BeTrue())
			})

			It("should support inserting subdomains", func() {
				subdomain := "www." + domainOk

				Expect(sut.HasParentOf(subdomain)).Should(BeTrue())
				sut.Insert(subdomain)
				Expect(sut.HasParentOf(subdomain)).Should(BeTrue())
			})

			It("should not find unrelated", func() {
				Expect(sut.HasParentOf(domainKo)).Should(BeFalse())
			})

			It("should not find uninserted parent", func() {
				Expect(sut.HasParentOf(domainOkTLD)).Should(BeFalse())
			})

			It("should not find deep uninserted parent", func() {
				sut.Insert("sub.sub.sub.test")

				Expect(sut.HasParentOf("sub.sub.test")).Should(BeFalse())
			})

			It("should find inserted parent", func() {
				sut.Insert(domainOkTLD)
				Expect(sut.HasParentOf(domainOkTLD)).Should(BeTrue())
			})

			It("should insert sibling", func() {
				sibling := "other." + domainOkTLD

				sut.Insert(sibling)
				Expect(sut.HasParentOf(sibling)).Should(BeTrue())
			})

			It("should insert grand-children siblings", func() {
				base := "other.com"
				abcSub := "abc." + base
				xyzSub := "xyz." + base

				sut.Insert(abcSub)
				Expect(sut.HasParentOf(abcSub)).Should(BeTrue())
				Expect(sut.HasParentOf(xyzSub)).Should(BeFalse())
				Expect(sut.HasParentOf(base)).Should(BeFalse())

				sut.Insert(xyzSub)
				Expect(sut.HasParentOf(xyzSub)).Should(BeTrue())
				Expect(sut.HasParentOf(abcSub)).Should(BeTrue())
				Expect(sut.HasParentOf(base)).Should(BeFalse())
			})
		})
	})
})
