package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/0xERR0R/blocky/config"
	"github.com/creasty/defaults"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP router", func() {
	var cfg config.Config

	BeforeEach(func() {
		Expect(defaults.Set(&cfg)).Should(Succeed())
	})

	get := func(path string) *httptest.ResponseRecorder {
		router := createHTTPRouter(&cfg, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		return rec
	}

	rootBody := func() string {
		body, err := io.ReadAll(get("/").Result().Body)
		Expect(err).Should(Succeed())

		return string(body)
	}

	When("pprof is enabled (default)", func() {
		It("serves the pprof endpoints and links them on the root page", func() {
			Expect(cfg.Pprof.Enable).Should(BeTrue())
			Expect(get("/debug/pprof/cmdline").Code).Should(Equal(http.StatusOK))
			Expect(rootBody()).Should(ContainSubstring(`href="/debug/"`))
		})
	})

	When("pprof is disabled", func() {
		BeforeEach(func() {
			cfg.Pprof.Enable = false
		})

		It("does not serve the pprof endpoints nor link them on the root page", func() {
			Expect(get("/debug/pprof/cmdline").Code).Should(Equal(http.StatusNotFound))
			Expect(get("/debug/pprof/").Code).Should(Equal(http.StatusNotFound))
			Expect(rootBody()).ShouldNot(ContainSubstring(`/debug/`))
		})
	})
})

var _ = Describe("getSmallestTTLFromAnswer", func() {
	answerWithTTLs := func(ttls ...uint32) *dns.Msg {
		msg := new(dns.Msg)

		for _, ttl := range ttls {
			rr, err := dns.NewRR(fmt.Sprintf("example.com. %d IN A 192.0.2.1", ttl))
			Expect(err).Should(Succeed())

			msg.Answer = append(msg.Answer, rr)
		}

		return msg
	}

	DescribeTable("returns the smallest TTL of the answer section",
		func(expected uint32, ttls ...uint32) {
			Expect(getSmallestTTLFromAnswer(answerWithTTLs(ttls...))).Should(Equal(expected))
		},
		Entry("no answer", uint32(0)),
		Entry("single record", uint32(123), uint32(123)),
		Entry("smallest record last", uint32(60), uint32(300), uint32(60)),
		Entry("smallest record first", uint32(60), uint32(60), uint32(300)),
		Entry("zero TTL last", uint32(0), uint32(60), uint32(0)),
		Entry("zero TTL first", uint32(0), uint32(0), uint32(60)),
	)
})
