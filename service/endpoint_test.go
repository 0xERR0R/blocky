package service

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Endpoints", func() {
	Describe("EndpointsFromAddrs", func() {
		It("assigns the expected values", func() {
			Expect(EndpointsFromAddrs("proto", []string{":1", "localhost:2"})).Should(Equal([]Endpoint{
				{"proto", ":1"},
				{"proto", "localhost:2"},
			}))
		})
	})

	Describe("Endpoint", func() {
		It("strings to a URL", func() {
			sut := Endpoint{"proto", "addr:port/whatever!no format \000 expected?"}

			Expect(sut.String()).Should(Equal("proto://" + sut.AddrConf))
		})

		It("strings with explicit wildcard host", func() {
			sut := Endpoint{"https", ":443"}

			Expect(sut.String()).Should(Equal("https://*:443"))
		})
	})

	Describe("endpointSet", func() {
		e1 := Endpoint{"proto", ":1"}
		e2 := Endpoint{"proto", ":2"}
		e3 := Endpoint{"proto", ":3"}

		sut := newEndpointSet(e1, e1, e2)

		It("should contain all elements", func() {
			Expect(sut.ToSlice()).Should(SatisfyAll(HaveLen(2), ContainElements(e1, e2)))
		})

		It("should intersect common values", func() {
			sut.IntersectSlice([]Endpoint{e2, e3})
			Expect(sut.ToSlice()).Should(Equal([]Endpoint{e2}))
		})
	})
})
