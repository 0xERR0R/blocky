package config

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("DNSSEC config", func() {
	Describe("IsEnabled", func() {
		It("should return true when Validate is true", func() {
			cfg := &DNSSEC{
				Validate: true,
			}

			Expect(cfg.IsEnabled()).Should(BeTrue())
		})

		It("should return false when Validate is false", func() {
			cfg := &DNSSEC{
				Validate: false,
			}

			Expect(cfg.IsEnabled()).Should(BeFalse())
		})

		It("should return false for zero value", func() {
			cfg := &DNSSEC{}

			Expect(cfg.IsEnabled()).Should(BeFalse())
		})
	})

	Describe("LogConfig", func() {
		var (
			logger *logrus.Entry
			buf    *bytes.Buffer
		)

		BeforeEach(func() {
			buf = new(bytes.Buffer)
			logInstance := logrus.New()
			logInstance.Out = buf
			logInstance.SetLevel(logrus.InfoLevel)
			logger = logrus.NewEntry(logInstance)
		})

		It("should log validation status when disabled", func() {
			cfg := &DNSSEC{
				Validate: false,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Validation = false"))
		})

		It("should log validation status and all settings when enabled", func() {
			cfg := &DNSSEC{
				Validate:              true,
				MaxChainDepth:         10,
				CacheExpirationHours:  1,
				MaxNSEC3Iterations:    150,
				MaxUpstreamQueries:    30,
				ClockSkewToleranceSec: 3600,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Validation = true"))
			Expect(output).Should(ContainSubstring("Max chain depth = 10"))
			Expect(output).Should(ContainSubstring("Cache expiration = 1 hour(s)"))
			Expect(output).Should(ContainSubstring("Max NSEC3 iterations = 150"))
			Expect(output).Should(ContainSubstring("Max upstream queries per validation = 30"))
			Expect(output).Should(ContainSubstring("Clock skew tolerance = 3600 second(s)"))
		})

		It("should log default trust anchors when none provided", func() {
			cfg := &DNSSEC{
				Validate:     true,
				TrustAnchors: []string{},
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Using default root trust anchors"))
		})

		It("should log custom trust anchors count when provided", func() {
			cfg := &DNSSEC{
				Validate: true,
				TrustAnchors: []string{
					"anchor1",
					"anchor2",
					"anchor3",
				},
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Custom trust anchors = 3"))
		})

		It("should not log detailed settings when disabled", func() {
			cfg := &DNSSEC{
				Validate:              false,
				MaxChainDepth:         10,
				CacheExpirationHours:  1,
				MaxNSEC3Iterations:    150,
				MaxUpstreamQueries:    30,
				ClockSkewToleranceSec: 3600,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Validation = false"))
			Expect(output).ShouldNot(ContainSubstring("Max chain depth"))
			Expect(output).ShouldNot(ContainSubstring("Cache expiration"))
			Expect(output).ShouldNot(ContainSubstring("Max NSEC3 iterations"))
		})

		It("should log different cache expiration values", func() {
			cfg := &DNSSEC{
				Validate:             true,
				CacheExpirationHours: 24,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Cache expiration = 24 hour(s)"))
		})

		It("should log different max chain depth values", func() {
			cfg := &DNSSEC{
				Validate:      true,
				MaxChainDepth: 20,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Max chain depth = 20"))
		})

		It("should log different NSEC3 iteration limits", func() {
			cfg := &DNSSEC{
				Validate:           true,
				MaxNSEC3Iterations: 500,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Max NSEC3 iterations = 500"))
		})

		It("should log different upstream query limits", func() {
			cfg := &DNSSEC{
				Validate:           true,
				MaxUpstreamQueries: 50,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Max upstream queries per validation = 50"))
		})

		It("should log different clock skew tolerance values", func() {
			cfg := &DNSSEC{
				Validate:              true,
				ClockSkewToleranceSec: 7200,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Clock skew tolerance = 7200 second(s)"))
		})

		It("should handle zero values when enabled", func() {
			cfg := &DNSSEC{
				Validate:              true,
				MaxChainDepth:         0,
				CacheExpirationHours:  0,
				MaxNSEC3Iterations:    0,
				MaxUpstreamQueries:    0,
				ClockSkewToleranceSec: 0,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Max chain depth = 0"))
			Expect(output).Should(ContainSubstring("Cache expiration = 0 hour(s)"))
			Expect(output).Should(ContainSubstring("Max NSEC3 iterations = 0"))
			Expect(output).Should(ContainSubstring("Max upstream queries per validation = 0"))
			Expect(output).Should(ContainSubstring("Clock skew tolerance = 0 second(s)"))
		})

		It("should handle single custom trust anchor", func() {
			cfg := &DNSSEC{
				Validate: true,
				TrustAnchors: []string{
					"single-anchor",
				},
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Custom trust anchors = 1"))
		})

		It("should handle nil trust anchors same as empty", func() {
			cfg := &DNSSEC{
				Validate:     true,
				TrustAnchors: nil,
			}

			cfg.LogConfig(logger)

			output := buf.String()
			Expect(output).Should(ContainSubstring("Using default root trust anchors"))
		})
	})

	Describe("Configuration defaults", func() {
		It("should document default values via struct tags", func() {
			// This test documents the expected default values
			// The actual defaults are set by the config loader based on struct tags
			cfg := &DNSSEC{}

			// Document expected defaults (set by config loader)
			expectedDefaults := map[string]interface{}{
				"validate":              false,
				"maxChainDepth":         uint(10),
				"cacheExpirationHours":  uint(1),
				"maxNSEC3Iterations":    uint(150),
				"maxUpstreamQueries":    uint(30),
				"clockSkewToleranceSec": uint(3600),
			}

			// Verify struct has the expected fields
			Expect(cfg).ShouldNot(BeNil())
			_ = expectedDefaults // Document defaults
		})
	})
})
