package service

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Service", func() {
	var err error

	Describe("Info", func() {
		endpoints := EndpointsFromAddrs("proto", []string{":1", "localhost:2"})
		sut := NewInfo("name", endpoints)

		It("implements Service", func() {
			var svc Service = &sut

			Expect(svc.ServiceName()).Should(Equal("name"))

			Expect(svc.ExposeOn()).Should(Equal(endpoints))

			Expect(svc.String()).Should(SatisfyAll(
				ContainSubstring("name"),
				ContainSubstring(":1"),
				ContainSubstring("localhost:2"),
			))
		})
	})

	Describe("GroupByListener", func() {
		httpSvcA1 := newFakeHTTPService("HTTP A1", "a:1")
		httpSvcA1_ := newFakeHTTPService("HTTP A1_", "a:1")
		httpSvcA2 := newFakeHTTPService("HTTP A2", "a:2")
		httpSvcB1 := newFakeHTTPService("HTTP B1", "b:1")

		httpLnrA1 := &NetListener{nil, ListenerInfo{Endpoint{"http", "a:1"}}}
		httpLnrA2 := &NetListener{nil, ListenerInfo{Endpoint{"http", "a:2"}}}
		httpLnrB1 := &NetListener{nil, ListenerInfo{Endpoint{"http", "b:1"}}}

		It("assigns single service to matching listener", func() {
			Expect(
				GroupByListener([]Service{httpSvcA1}, []Listener{httpLnrA1}),
			).Should(Equal(map[Listener]Service{httpLnrA1: httpSvcA1}))
		})

		It("assigns each service to the matching listener", func() {
			Expect(
				GroupByListener([]Service{httpSvcA1, httpSvcA2, httpSvcB1}, []Listener{httpLnrA1, httpLnrA2, httpLnrB1}),
			).Should(Equal(map[Listener]Service{
				httpLnrA1: httpSvcA1,
				httpLnrA2: httpSvcA2,
				httpLnrB1: httpSvcB1,
			}))
		})

		It("merges services with a common endpoint", func() {
			merged, err := MergeAll(httpSvcA1, httpSvcA1_)
			Expect(err).Should(Succeed())

			Expect(
				GroupByListener([]Service{httpSvcA1, httpSvcA1_}, []Listener{httpLnrA1}),
			).Should(Equal(map[Listener]Service{httpLnrA1: merged}))
		})

		It("fails when a service has no compatible listener", func() {
			_, err = GroupByListener([]Service{httpSvcA1, httpSvcA1_}, nil)
			Expect(err).Should(MatchError(ContainSubstring("no compatible listener")))

			_, err = GroupByListener([]Service{httpSvcA1, httpSvcA1_, httpSvcA2}, []Listener{httpLnrA2})
			Expect(err).Should(MatchError(ContainSubstring("no compatible listener")))
		})

		It("fails when a listener has no compatible services", func() {
			_, err = GroupByListener(nil, []Listener{httpLnrA2})
			Expect(err).Should(MatchError(ContainSubstring("no compatible services")))

			_, err = GroupByListener([]Service{httpSvcA1, httpSvcA1_}, []Listener{httpLnrA2})
			Expect(err).Should(MatchError(ContainSubstring("no compatible services")))
		})

		It("fails when services with a common endpoint are not mergeable", func() {
			nonMergeable := &Info{"non mergeable", EndpointsFromAddrs("http", []string{"a:1"})}

			_, err = GroupByListener([]Service{httpSvcA1, nonMergeable}, []Listener{httpLnrA1})
			Expect(err).Should(MatchError(ContainSubstring("cannot merge services")))
		})
	})
})
