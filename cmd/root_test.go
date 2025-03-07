package cmd

import (
	"io"
	"net/http"
	"os"

	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/0xERR0R/blocky/helpertest"
)

// Mock implementation of codeWithStatus interface for testing
type mockResponse struct {
	statusCode int
	status     string
}

func (m mockResponse) StatusCode() int {
	return m.statusCode
}

func (m mockResponse) Status() string {
	return m.status
}

var _ = Describe("root command", func() {
	When("Version command is called", func() {
		log.Log().ExitFunc = nil
		It("should execute without error", func() {
			c := NewRootCommand()
			c.SetOut(io.Discard)
			c.SetArgs([]string{"help"})
			err := c.Execute()
			Expect(err).Should(Succeed())
		})
	})

	When("Config provided", func() {
		var (
			tmpDir  *TmpFolder
			tmpFile *TmpFile
		)

		BeforeEach(func() {
			configPath = defaultConfigPath

			tmpDir = NewTmpFolder("RootCommand")
			tmpFile = tmpDir.CreateStringFile("config",
				"upstreams:",
				"  groups:",
				"    default:",
				"      - 1.1.1.1",
				"blocking:",
				"  denylists:",
				"    ads:",
				"      - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
				"  clientGroupsBlock:",
				"    default:",
				"      - ads",
				"port: 5333",
			)
		})

		It("should accept old env var", func() {
			os.Setenv(configFileEnvVarOld, tmpFile.Path)
			DeferCleanup(func() { os.Unsetenv(configFileEnvVarOld) })

			Expect(initConfig()).Should(Succeed())

			Expect(configPath).Should(Equal(tmpFile.Path))
		})

		It("should accept new env var", func() {
			os.Setenv(configFileEnvVar, tmpFile.Path)
			DeferCleanup(func() { os.Unsetenv(configFileEnvVar) })

			Expect(initConfig()).Should(Succeed())

			Expect(configPath).Should(Equal(tmpFile.Path))
		})

		It("should handle config with HTTP port", func() {
			configWithHTTP := tmpDir.CreateStringFile("config_with_http",
				"upstreams:",
				"  groups:",
				"    default:",
				"      - 1.1.1.1",
				"ports:",
				"  http:",
				"    - 127.0.0.1:8080",
			)

			configPath = configWithHTTP.Path

			Expect(initConfig()).Should(Succeed())
			Expect(apiHost).Should(Equal("127.0.0.1"))
			Expect(apiPort).Should(Equal(uint16(8080)))
		})

		It("should handle config with invalid HTTP port", func() {
			configWithInvalidHTTP := tmpDir.CreateStringFile("config_with_invalid_http",
				"upstreams:",
				"  groups:",
				"    default:",
				"      - 1.1.1.1",
				"ports:",
				"  http:",
				"    - 127.0.0.1:invalid",
			)

			configPath = configWithInvalidHTTP.Path

			err := initConfig()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("can't convert port"))
		})
	})

	Describe("apiURL function", func() {
		It("should return correct URL with default values", func() {
			apiHost = defaultHost
			apiPort = defaultPort

			url := apiURL()
			Expect(url).Should(Equal("http://localhost:4000/api"))
		})

		It("should return correct URL with custom values", func() {
			apiHost = "127.0.0.1"
			apiPort = 8080

			url := apiURL()
			Expect(url).Should(Equal("http://127.0.0.1:8080/api"))
		})
	})

	Describe("printOkOrError function", func() {
		It("should return nil for OK status", func() {
			resp := mockResponse{
				statusCode: http.StatusOK,
				status:     "200 OK",
			}

			err := printOkOrError(resp, "")
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should return error for non-OK status", func() {
			resp := mockResponse{
				statusCode: http.StatusBadRequest,
				status:     "400 Bad Request",
			}

			err := printOkOrError(resp, "Error message")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("400 Bad Request"))
			Expect(err.Error()).Should(ContainSubstring("Error message"))
		})
	})

	Describe("Command execution", func() {
		BeforeEach(func() {
			// Reset to default values before each test
			configPath = defaultConfigPath
			apiHost = defaultHost
			apiPort = defaultPort
		})

		It("should create root command with all subcommands", func() {
			cmd := NewRootCommand()

			// Check if all subcommands are added
			subCmdNames := []string{}
			for _, subCmd := range cmd.Commands() {
				subCmdNames = append(subCmdNames, subCmd.Name())
			}

			expectedCmds := []string{
				"refresh", "query", "version", "serve",
				"blocking", "lists", "healthcheck", "cache", "validate",
			}
			for _, expected := range expectedCmds {
				Expect(subCmdNames).Should(ContainElement(expected))
			}
		})

		It("should set flags correctly", func() {
			cmd := NewRootCommand()

			// Test config flag
			configFlag := cmd.PersistentFlags().Lookup("config")
			Expect(configFlag).ShouldNot(BeNil())
			Expect(configFlag.Shorthand).Should(Equal("c"))
			Expect(configFlag.DefValue).Should(Equal(defaultConfigPath))

			// Test apiHost flag
			apiHostFlag := cmd.PersistentFlags().Lookup("apiHost")
			Expect(apiHostFlag).ShouldNot(BeNil())
			Expect(apiHostFlag.DefValue).Should(Equal(defaultHost))

			// Test apiPort flag
			apiPortFlag := cmd.PersistentFlags().Lookup("apiPort")
			Expect(apiPortFlag).ShouldNot(BeNil())
			Expect(apiPortFlag.DefValue).Should(Equal("4000"))
		})
	})
})
