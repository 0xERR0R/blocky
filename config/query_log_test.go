package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
)

var _ = Describe("QueryLogConfig", func() {
	var cfg QueryLog

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = QueryLog{
			Target:           "/dev/null",
			Type:             QueryLogTypeCsvClient,
			LogRetentionDays: 0,
			CreationAttempts: 1,
			CreationCooldown: Duration(time.Millisecond),
		}
	})

	Describe("IsEnabled", func() {
		It("should be true by default", func() {
			cfg := QueryLog{}
			Expect(defaults.Set(&cfg)).Should(Succeed())

			Expect(cfg.IsEnabled()).Should(BeTrue())
		})

		When("enabled", func() {
			It("should be true", func() {
				Expect(cfg.IsEnabled()).Should(BeTrue())
			})
		})

		When("disabled", func() {
			It("should be false", func() {
				cfg := QueryLog{
					Type: QueryLogTypeNone,
				}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("logRetentionDays:")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("sudn:")))
		})

		It("should log the ignored domains", func() {
			cfg.Ignore.Domains = []string{"example.com", "*.lan", "/\\.arpa$/"}

			cfg.LogConfig(logger)

			Expect(hook.Messages).Should(ContainElement(ContainSubstring("domains (3):")))

		})

		DescribeTable("secret censoring", func(target string) {
			cfg.Type = QueryLogTypeMysql
			cfg.Target = Secret(target)

			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring("password")))
		},
			Entry("without scheme", "user:password@localhost"),
			Entry("with scheme", "scheme://user:password@localhost"),
			Entry("no password", "localhost"),
			Entry("not a URL", "invalid!://"),
		)
	})

	Describe("ignore.domains parsing", func() {
		It("parses the domains list", func() {
			yamlStr := "type: console\nignore:\n  domains:\n    - example.com\n    - \"*.lan\"\n"

			var qlCfg QueryLog
			Expect(yaml.UnmarshalStrict([]byte(yamlStr), &qlCfg)).Should(Succeed())
			Expect(qlCfg.Ignore.Domains).Should(Equal([]string{"example.com", "*.lan"}))
		})
	})

	Describe("secret target handling", func() {
		It("loads the target DSN from a file and censors it when logging", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "dsn")
			Expect(os.WriteFile(path, []byte("postgresql://u:secretpw@host/db\n"), 0o600)).Should(Succeed())

			yamlStr := "type: postgresql\ntarget: file:" + path + "\n"

			var qlCfg QueryLog
			Expect(yaml.UnmarshalStrict([]byte(yamlStr), &qlCfg)).Should(Succeed())
			Expect(qlCfg.Target.Reveal()).Should(Equal("postgresql://u:secretpw@host/db"))
			Expect(qlCfg.censoredTarget()).ShouldNot(ContainSubstring("secretpw"))
			Expect(qlCfg.censoredTarget()).Should(ContainSubstring(secretObfuscator))
		})

		It("censors the embedded password of an inline DSN", func() {
			cfg := QueryLog{Type: QueryLogTypePostgresql, Target: "postgresql://u:secretpw@host/db"}
			Expect(cfg.censoredTarget()).ShouldNot(ContainSubstring("secretpw"))
			Expect(cfg.censoredTarget()).Should(ContainSubstring(secretObfuscator))
		})
	})

	Describe("QueryLogType enum", func() {
		It("parses the sqlite type", func() {
			t, err := ParseQueryLogType("sqlite")
			Expect(err).Should(Succeed())
			Expect(t).Should(Equal(QueryLogTypeSqlite))
		})
	})

	Describe("SetDefaults", func() {
		It("should log configuration", func() {
			cfg := QueryLog{}
			Expect(cfg.Fields).Should(BeEmpty())

			Expect(defaults.Set(&cfg)).Should(Succeed())

			Expect(cfg.Fields).ShouldNot(BeEmpty())
		})
	})
})
