package cmd

import (
	"os"
	"path/filepath"

	"github.com/0xERR0R/blocky/helpertest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Reproduces #2218: the Docker image runs `blocky healthcheck` with no flags, but the
// command defaults to port 53 and never looks at `ports.dns`, so a container that
// listens on a different DNS port is reported unhealthy.
var _ = Describe("Healthcheck derives the port from the config (#2218)", func() {
	var cfgFile string

	writeConfig := func(body string) {
		dir := GinkgoT().TempDir()
		cfgFile = filepath.Join(dir, "config.yml")
		Expect(os.WriteFile(cfgFile, []byte(body), 0o600)).Should(Succeed())

		GinkgoT().Setenv("BLOCKY_CONFIG_FILE", cfgFile)

		// initConfig() only consults the env var while configPath is still the default.
		old := configPath
		configPath = defaultConfigPath
		DeferCleanup(func() { configPath = old })
	}

	It("probes the DNS port from ports.dns when no flag is given", func() {
		ip := "127.0.0.1"
		port := helpertest.GetStringPort(65111)
		hostPort := helpertest.GetHostPort(ip, 65111)

		srv := createMockServer(hostPort)
		go func() {
			defer GinkgoRecover()
			Expect(srv.ListenAndServe()).Should(Succeed())
		}()

		writeConfig("ports:\n  dns: " + port + "\nupstreams:\n  groups:\n    default:\n      - 1.1.1.1\n")

		Eventually(func() error {
			c := NewHealthcheckCommand()
			c.SetArgs([]string{})

			return c.Execute()
		}, "2s").Should(Succeed())
	})

	It("still lets an explicit --port win over the config", func() {
		ip := "127.0.0.1"
		port := helpertest.GetStringPort(65112)
		hostPort := helpertest.GetHostPort(ip, 65112)

		srv := createMockServer(hostPort)
		go func() {
			defer GinkgoRecover()
			Expect(srv.ListenAndServe()).Should(Succeed())
		}()

		// Config points somewhere nothing is listening; the flag must take precedence.
		writeConfig("ports:\n  dns: 65113\nupstreams:\n  groups:\n    default:\n      - 1.1.1.1\n")

		Eventually(func() error {
			c := NewHealthcheckCommand()
			c.SetArgs([]string{"-p", port, "-b", ip})

			return c.Execute()
		}, "2s").Should(Succeed())
	})

	It("keeps working when no config file exists at all", func() {
		ip := "127.0.0.1"
		port := helpertest.GetStringPort(65114)
		hostPort := helpertest.GetHostPort(ip, 65114)

		srv := createMockServer(hostPort)
		go func() {
			defer GinkgoRecover()
			Expect(srv.ListenAndServe()).Should(Succeed())
		}()

		GinkgoT().Setenv("BLOCKY_CONFIG_FILE", filepath.Join(GinkgoT().TempDir(), "does-not-exist.yml"))
		old := configPath
		configPath = defaultConfigPath
		DeferCleanup(func() { configPath = old })

		Eventually(func() error {
			c := NewHealthcheckCommand()
			c.SetArgs([]string{"-p", port, "-b", ip})

			return c.Execute()
		}, "2s").Should(Succeed())
	})
})
