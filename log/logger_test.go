package log

import (
	"bytes"
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

var _ = Describe("Logger", func() {
	var cfg *Config

	BeforeEach(func() {
		cfg = DefaultConfig()
	})

	Describe("target", func() {
		It("defaults to stdout", func() {
			Expect(cfg.Target).Should(Equal(TargetTypeStdout))
		})

		It("parses each accepted value", func() {
			Expect(ParseTargetType("stdout")).Should(Equal(TargetTypeStdout))
			Expect(ParseTargetType("stderr")).Should(Equal(TargetTypeStderr))
			Expect(ParseTargetType("syslog")).Should(Equal(TargetTypeSyslog))
		})

		It("rejects anything else", func() {
			_, err := ParseTargetType("nowhere")
			Expect(err).Should(HaveOccurred())
		})
	})

	Describe("syslog", func() {
		It("defaults to the daemon facility and the blocky tag", func() {
			Expect(cfg.Syslog.Facility).Should(Equal(SyslogFacility("daemon")))
			Expect(cfg.Syslog.Tag).Should(Equal("blocky"))
		})

		It("keeps logging when syslog can't be used", func() {
			cfg.Target = TargetTypeSyslog
			cfg.Syslog.Facility = "not-a-facility"

			logger := logrus.New()
			ConfigureLogger(logger, cfg)

			out := new(bytes.Buffer)
			logger.SetOutput(out)
			logger.Warn("still here")

			Expect(out.String()).Should(ContainSubstring("still here"))
		})
	})

	Describe("Silence", func() {
		It("leaves a logger that still logs the fields of a context", func() {
			original := logger
			DeferCleanup(func() { logger = original })

			Silence()

			hook := test.NewLocal(logger)

			FromCtx(CtxWithFields(context.Background(), logrus.Fields{"a": 1})).Info("message")

			Expect(hook.LastEntry().Data).Should(Equal(logrus.Fields{"a": 1}))
		})
	})
})
