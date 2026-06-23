package cmd

import (
	"errors"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("warnMissingPrivilegedPortCapability", func() {
	var (
		rec       *log.Recorder
		origRaise func() (bool, error)
	)

	BeforeEach(func() {
		origRaise = raiseNetBindService
		var restore func()
		rec, restore = log.CaptureGlobal()
		DeferCleanup(restore)
	})

	AfterEach(func() {
		raiseNetBindService = origRaise
	})

	When("the capability is effective", func() {
		BeforeEach(func() {
			raiseNetBindService = func() (bool, error) { return true, nil }
		})

		It("does not warn even with a privileged port", func() {
			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":53"}})
			Expect(rec.Records()).Should(BeEmpty())
		})
	})

	When("the capability is not effective", func() {
		BeforeEach(func() {
			raiseNetBindService = func() (bool, error) { return false, nil }
		})

		It("warns when a privileged port is configured", func() {
			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":53"}})
			Expect(rec.LastMessage()).Should(ContainSubstring("CAP_NET_BIND_SERVICE"))
		})

		It("does not warn when only unprivileged ports are configured", func() {
			warnMissingPrivilegedPortCapability(config.Ports{
				DNS:  config.ListenConfig{":1053"},
				HTTP: config.ListenConfig{":4000"},
			})
			Expect(rec.Records()).Should(BeEmpty())
		})
	})

	When("raising the capability returns an error", func() {
		BeforeEach(func() {
			raiseNetBindService = func() (bool, error) { return false, errors.New("boom") }
		})

		It("logs one combined warning naming the error and the capability", func() {
			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":53"}})
			Expect(rec.Records()).Should(HaveLen(1))
			Expect(rec.LastMessage()).Should(SatisfyAll(
				ContainSubstring("could not adjust process capabilities"),
				ContainSubstring("CAP_NET_BIND_SERVICE"),
			))
		})

		It("logs only the error when no privileged port is configured", func() {
			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":1053"}})
			Expect(rec.Records()).Should(HaveLen(1))
			Expect(rec.LastMessage()).Should(ContainSubstring("could not adjust process capabilities"))
			Expect(rec.LastMessage()).ShouldNot(ContainSubstring("CAP_NET_BIND_SERVICE"))
		})
	})
})
