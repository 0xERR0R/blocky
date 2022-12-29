package resolver

import (
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NoOpResolver", func() {
	var sut NoOpResolver

	BeforeEach(func() {
		sut = NewNoOpResolver().(NoOpResolver)
	})

	Describe("Resolving", func() {
		It("returns no response", func() {
			resp, err := sut.Resolve(newRequest("test.tld", A))
			Expect(err).Should(Succeed())
			Expect(resp).Should(Equal(NoResponse))
		})
	})

	Describe("Configuration output", func() {
		It("returns nothing", func() {
			c := sut.Configuration()
			Expect(c).Should(BeNil())
		})
	})
})
