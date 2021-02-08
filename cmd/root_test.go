package cmd

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("Version command", func() {
	When("Version command is called", func() {
		logrus.StandardLogger().ExitFunc = nil
		It("should execute without error", func() {
			c := NewRootCommand()
			c.SetArgs([]string{"help"})
			err := c.Execute()
			Expect(err).Should(Succeed())
		})
	})
})
