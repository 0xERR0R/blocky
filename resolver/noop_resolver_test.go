package resolver

import (
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NoOpResolver", func() {
	var sut NoOpResolver

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

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

	Describe("IsEnabled", func() {
		It("is true", func() {
			Expect(sut.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		It("should not log anything", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).Should(BeEmpty())
		})
	})
})
