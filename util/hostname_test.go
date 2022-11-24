package util

import (
	"os"
	"strings"

	"github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hostname function tests", func() {
	When("file is present", func() {
		var (
			tmpDir *helpertest.TmpFolder
		)

		BeforeEach(func() {
			tmpDir = helpertest.NewTmpFolder("hostname")
			Expect(tmpDir.Error).Should(Succeed())
			DeferCleanup(tmpDir.Clean)
		})

		It("should be used", func() {
			tmpFile := tmpDir.CreateStringFile("filetest1", "TestName ")
			Expect(tmpFile.Error).Should(Succeed())
			getHostname(tmpFile.Path)

			fhn, err := os.ReadFile(tmpFile.Path)
			Expect(err).Should(Succeed())

			hn, err := Hostname()
			Expect(err).Should(Succeed())

			Expect(hn).Should(Equal(strings.TrimSpace(string(fhn))))
		})
	})

	When("file is not present", func() {
		It("should use os.Hostname", func() {
			getHostname("/does-not-exist")

			_, err := Hostname()
			Expect(err).Should(Succeed())

			ohn, err := os.Hostname()
			Expect(err).Should(Succeed())

			Expect(HostnameString()).Should(Equal(ohn))
		})
	})
})
