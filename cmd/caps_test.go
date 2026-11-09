package cmd

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"

	"github.com/sirupsen/logrus/hooks/test"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("warnMissingPrivilegedPortCapability", func() {
	var (
		loggerHook    *test.Hook
		origRaise     func() (bool, error)
		origStartFile string
	)

	// setUnprivilegedPortStart writes a fake net.ipv4.ip_unprivileged_port_start.
	setUnprivilegedPortStart := func(value string) {
		path := filepath.Join(GinkgoT().TempDir(), "ip_unprivileged_port_start")
		Expect(os.WriteFile(path, []byte(value), 0o600)).Should(Succeed())
		unprivilegedPortStartFile = path
	}

	BeforeEach(func() {
		origRaise = raiseNetBindService
		origStartFile = unprivilegedPortStartFile
		// Don't depend on the sysctl of the machine running the tests.
		unprivilegedPortStartFile = filepath.Join(GinkgoT().TempDir(), "missing")
		loggerHook = test.NewGlobal()
		log.Log().AddHook(loggerHook)
	})

	AfterEach(func() {
		raiseNetBindService = origRaise
		unprivilegedPortStartFile = origStartFile
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

		It("does not warn when ip_unprivileged_port_start is 0, as Docker sets it", func() {
			setUnprivilegedPortStart("0\n")

			warnMissingPrivilegedPortCapability(config.Ports{
				DNS:  config.ListenConfig{":53"},
				HTTP: config.ListenConfig{":80"},
			})
			Expect(loggerHook.AllEntries()).Should(BeEmpty())
		})

		It("warns only about ports below ip_unprivileged_port_start", func() {
			setUnprivilegedPortStart("80\n")

			warnMissingPrivilegedPortCapability(config.Ports{
				DNS:  config.ListenConfig{":53"},
				HTTP: config.ListenConfig{":80"},
			})
			Expect(loggerHook.AllEntries()).Should(HaveLen(1))
			Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("port(s) :53 without"))
		})

		It("falls back to ports below 1024 when the sysctl can't be parsed", func() {
			setUnprivilegedPortStart("garbage\n")

			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":53"}})
			Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("CAP_NET_BIND_SERVICE"))
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

		It("logs only the error when ip_unprivileged_port_start is 0", func() {
			setUnprivilegedPortStart("0\n")

			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":53"}})
			Expect(loggerHook.AllEntries()).Should(HaveLen(1))
			Expect(loggerHook.LastEntry().Message).ShouldNot(ContainSubstring("CAP_NET_BIND_SERVICE"))
		})

		It("logs only the error when no privileged port is configured", func() {
			warnMissingPrivilegedPortCapability(config.Ports{DNS: config.ListenConfig{":1053"}})
			Expect(loggerHook.AllEntries()).Should(HaveLen(1))
			Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("could not adjust process capabilities"))
			Expect(loggerHook.LastEntry().Message).ShouldNot(ContainSubstring("CAP_NET_BIND_SERVICE"))
		})
	})
})
