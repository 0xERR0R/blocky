package cmd

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Serve command", func() {
	var (
		tmpDir *helpertest.TmpFolder
		port   string
	)
	BeforeEach(func() {
		// A fresh port per spec. Nothing here has to reuse one, and the spec
		// below deliberately occupies its port for the rest of the spec.
		port = strconv.Itoa(helpertest.NextFreePort())
		tmpDir = helpertest.NewTmpFolder("config")

		configPath = defaultConfigPath
	})

	When("Serve command is called with valid config", func() {
		It("should start without error and terminate with signal", func() {
			By("initialize config", func() {
				cfgFile := tmpDir.CreateStringFile("config.yaml",
					"databasePath: "+tmpDir.Path+"/blocky.db",
					"ports:",
					"  dns: "+port)

				os.Setenv(configFileEnvVar, cfgFile.Path)
				DeferCleanup(func() { os.Unsetenv(configFileEnvVar) })

				Expect(initConfig()).Should(Succeed())
			})

			errChan := make(chan error)
			By("start server", func() {
				go func() {
					// it is a blocking function, call async
					errChan <- startServer(newServeCommand(), []string{})
				}()
			})

			By("check DNS port is open", func() {
				Eventually(func(g Gomega) {
					conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond)
					g.Expect(err).Should(Succeed())
					defer conn.Close()
				}, "5s").Should(Succeed())
			})

			By("terminate with signal", func() {
				signals <- syscall.SIGINT

				// no errors
				Eventually(errChan).Should(Receive(BeNil()))
			})
		})
	})

	// This spec makes blocky lose a bind on purpose, so a passing run still logs
	// `server start failed: ... bind: address already in use`. That line is the
	// assertion below succeeding, not a flake — it has been read as one.
	When("Serve command is called with valid config", func() {
		It("should fail if server start fails", func() {
			By("occupy port "+port, func() {
				// A listener, not an http.Server: all this spec needs is for
				// blocky's bind to lose. The previous version leaked an
				// http.ListenAndServe goroutine that held the port — and
				// asserted from a goroutine with no GinkgoRecover — for the
				// rest of the suite process.
				blocker, err := net.Listen("tcp", ":"+port)
				Expect(err).Should(Succeed())
				DeferCleanup(blocker.Close)
			})
			By("initialize config with blocked port "+port, func() {
				cfgFile := tmpDir.CreateStringFile("config.yaml",
					"databasePath: "+tmpDir.Path+"/blocky.db",
					"ports:",
					"  dns: "+port)

				os.Setenv(configFileEnvVar, cfgFile.Path)
				DeferCleanup(func() { os.Unsetenv(configFileEnvVar) })

				Expect(initConfig()).Should(Succeed())
			})

			errChan := make(chan error)
			By("start server", func() {
				go func() {
					// it is a blocking function, call async
					errChan <- startServer(newServeCommand(), []string{})
				}()
			})

			By("terminate with signal", func() {
				var startError error
				Eventually(errChan, "10s").Should(Receive(&startError))
				Expect(startError).Should(MatchError(ContainSubstring("address already in use")))
			})
		})
	})

	When("Serve command is called without config", func() {
		It("should fail to start and report error", func() {
			errChan := make(chan error)
			By("start server", func() {
				go func() {
					// it is a blocking function, call async
					errChan <- startServer(newServeCommand(), []string{})
				}()
			})

			By("server should terminate with error", func() {
				var startError error
				Eventually(errChan).Should(Receive(&startError))
				Expect(startError).Should(MatchError(ContainSubstring("unable to load configuration")))
			})
		})
	})
})
