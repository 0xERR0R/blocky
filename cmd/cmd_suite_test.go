package cmd

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

var (
	fatal      bool
	loggerHook *test.Hook
)

func TestCmd(t *testing.T) {
	BeforeSuite(func() {
		logrus.StandardLogger().ExitFunc = func(int) { fatal = true }

		loggerHook = test.NewGlobal()
	})
	AfterSuite(func() {
		logrus.StandardLogger().ExitFunc = nil
		loggerHook.Reset()
	})
	RegisterFailHandler(Fail)
	RunSpecs(t, "Command Suite")
}
