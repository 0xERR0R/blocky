package cmd

import (
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Serve command", func() {
	var tmpDir *helpertest.TmpFolder
	BeforeEach(func() {
		tmpDir = helpertest.NewTmpFolder("config")
		Expect(tmpDir.Error).Should(Succeed())
		DeferCleanup(tmpDir.Clean)
		configPath = defaultConfigPath
	})

	When("Serve command is called with valid config", func() {
		It("should start without error and terminate with signal", func() {
			By("initialize config", func() {
				cfgFile := tmpDir.CreateStringFile("config.yaml",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - 1.1.1.1",
					"ports:",
					"  dns: 55555")
				Expect(cfgFile.Error).Should(Succeed())
				os.Setenv(configFileEnvVar, cfgFile.Path)
				DeferCleanup(func() { os.Unsetenv(configFileEnvVar) })
				initConfig()
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
					conn, err := net.DialTimeout("tcp", "127.0.0.1:55555", 200*time.Millisecond)
					g.Expect(err).Should(Succeed())
					defer conn.Close()
				}).Should(Succeed())
			})

			By("terminate with signal", func() {
				signals <- syscall.SIGINT

				// no errors
				Eventually(errChan).Should(Receive(BeNil()))
			})
		})
	})

	When("Serve command is called with valid config", func() {
		It("should fail if server start fails", func() {
			By("start http server on port 5555", func() {
				go func() {
					Expect(http.ListenAndServe(":55555", nil)).Should(Succeed())
				}()
			})
			By("initialize config with blocked port 55555", func() {
				cfgFile := tmpDir.CreateStringFile("config.yaml",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - 1.1.1.1",
					"ports:",
					"  dns: 55555")
				Expect(cfgFile.Error).Should(Succeed())
				os.Setenv(configFileEnvVar, cfgFile.Path)
				DeferCleanup(func() { os.Unsetenv(configFileEnvVar) })
				initConfig()
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
				Eventually(errChan).Should(Receive(&startError))
				Expect(startError).ShouldNot(BeNil())
				Expect(startError.Error()).Should(ContainSubstring("address already in use"))
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
				Expect(startError).ShouldNot(BeNil())
				Expect(startError.Error()).Should(ContainSubstring("unable to load configuration"))
			})
		})
	})
})
