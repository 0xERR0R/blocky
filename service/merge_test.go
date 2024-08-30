package service

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Service Merge", func() {
	var err error

	Describe("MergeAll", func() {
		httpSvcA1 := newFakeHTTPService("HTTP A1", "a:1")
		httpSvcA1_ := newFakeHTTPService("HTTP A1_", "a:1")

		nonMergeableSvc := &Info{"non mergeable", EndpointsFromAddrs("http", []string{"a:1"})}

		It("fails when no services are given", func() {
			_, err = MergeAll()
			Expect(err).Should(MatchError(ContainSubstring("no services")))
		})

		It("does not fail for a single non mergeable service", func() {
			Expect(MergeAll(nonMergeableSvc)).Should(BeIdenticalTo(nonMergeableSvc))
		})

		It("fails when no service is mergeable", func() {
			_, err = MergeAll(nonMergeableSvc, nonMergeableSvc)
			Expect(err).Should(MatchError(ContainSubstring("no merger found")))
		})

		It("merges services", func() {
			merged, err := MergeAll(httpSvcA1, httpSvcA1_)
			Expect(err).Should(Succeed())
			Expect(merged.String()).Should(SatisfyAll(
				ContainSubstring(httpSvcA1.ServiceName()),
				ContainSubstring(httpSvcA1_.ServiceName())),
			)
			Expect(merged.ExposeOn()).Should(Equal(httpSvcA1.ExposeOn()))
		})
	})
})
