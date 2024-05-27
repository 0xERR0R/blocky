package cmd

import (
	"io"
	"os"

	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/0xERR0R/blocky/helpertest"
)

var _ = Describe("root command", func() {
	When("Version command is called", func() {
		log.Log().ExitFunc = nil
		It("should execute without error", func() {
			c := NewRootCommand()
			c.SetOutput(io.Discard)
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
	})
})
