package cmd

import (
	"os"

	"github.com/0xERR0R/blocky/config"
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
			c.SetArgs([]string{"version"})
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
			Expect(tmpDir.Error).Should(Succeed())
			DeferCleanup(tmpDir.Clean)

			tmpFile = tmpDir.CreateStringFile("config",
				"upstream:",
				"  default:",
				"    - 1.1.1.1",
				"blocking:",
				"  blackLists:",
				"    ads:",
				"      - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
				"  clientGroupsBlock:",
				"    default:",
				"      - ads",
				"port: 5333",
			)
			Expect(tmpFile.Error).Should(Succeed())
		})

		It("should accept old env var", func() {
			os.Setenv(config.ConfigFilePathOld, tmpFile.Path)
			DeferCleanup(func() { os.Unsetenv(config.ConfigFilePathOld) })

			initConfig()

			Expect(configPath).Should(Equal(tmpFile.Path))
		})

		It("should accept new env var", func() {
			os.Setenv(config.ConfigFilePath, tmpFile.Path)
			DeferCleanup(func() { os.Unsetenv(config.ConfigFilePath) })

			initConfig()

			Expect(configPath).Should(Equal(tmpFile.Path))
		})
	})
})
