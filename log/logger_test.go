package log

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Logger", func() {
	When("hostname file is provided", func() {
		var (
			tmpFile *os.File
			err     error
		)
		JustBeforeEach(func() {
			tmpFile, err = os.CreateTemp("", "prefix")
			Expect(err).Should(Succeed())
			_, err = tmpFile.WriteString("Test-Hostname")
			Expect(err).Should(Succeed())
			DeferCleanup(func() { os.Remove(tmpFile.Name()) })
		})
		It("should use it", func() {
			hostname, err := getHostname(tmpFile.Name())
			Expect(err).Should(Succeed())
			Expect(hostname).Should(Equal("test-hostname"))
		})
	})
	When("hostname file is not provided", func() {
		hostname1, err := os.Hostname()
		Expect(err).Should(Succeed())
		hostname2, err := getHostname("")
		Expect(err).Should(Succeed())
		Expect(hostname2).Should(Equal(hostname1))
	})
})
