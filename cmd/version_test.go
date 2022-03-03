package cmd

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version command", func() {
	When("Version command is called", func() {
		It("should execute without error", func() {
			c := NewVersionCommand()
			c.SetArgs(make([]string, 0))
			err := c.Execute()
			Expect(err).Should(Succeed())
		})
	})
})
