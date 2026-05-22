package cmd

import (
	"errors"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"

	"github.com/sirupsen/logrus/hooks/test"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("warnMissingPrivilegedPortCapability", func() {
	var (
		loggerHook *test.Hook
		origRaise  func() (bool, error)
	)

	BeforeEach(func() {
		origRaise = raiseNetBindService
		loggerHook = test.NewGlobal()
		log.Log().AddHook(loggerHook)
	})

	AfterEach(func() {
		raiseNetBindService = origRaise
		loggerHook.Reset()
	})

	When("the capability is effective", func() {
		BeforeEach(func() {
			raiseNetBindService = func() (bool, error) { return true, nil }
		})

		It("does not warn even with a privileged port", func() {
			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":53"}})
			Expect(loggerHook.AllEntries()).Should(BeEmpty())
		})
	})

	When("the capability is not effective", func() {
		BeforeEach(func() {
			raiseNetBindService = func() (bool, error) { return false, nil }
		})

		It("warns when a privileged port is configured", func() {
			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":53"}})
			Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("CAP_NET_BIND_SERVICE"))
		})

		It("does not warn when only unprivileged ports are configured", func() {
			warnMissingPrivilegedPortCapability(config.Ports{
				DNS:  config.ListenConfig{":1053"},
				HTTP: config.ListenConfig{":4000"},
			})
			Expect(loggerHook.AllEntries()).Should(BeEmpty())
		})
	})

	When("raising the capability returns an error", func() {
		BeforeEach(func() {
			raiseNetBindService = func() (bool, error) { return false, errors.New("boom") }
		})

		It("logs one combined warning naming the error and the capability", func() {
			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":53"}})
			Expect(loggerHook.AllEntries()).Should(HaveLen(1))
			Expect(loggerHook.LastEntry().Message).Should(SatisfyAll(
				ContainSubstring("could not adjust process capabilities"),
				ContainSubstring("CAP_NET_BIND_SERVICE"),
			))
		})

		It("logs only the error when no privileged port is configured", func() {
			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":1053"}})
			Expect(loggerHook.AllEntries()).Should(HaveLen(1))
			Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("could not adjust process capabilities"))
			Expect(loggerHook.LastEntry().Message).ShouldNot(ContainSubstring("CAP_NET_BIND_SERVICE"))
		})
	})
})
