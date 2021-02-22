package cmd

import (
	"blocky/log"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus/hooks/test"
)

var (
	fatal      bool
	loggerHook *test.Hook
)

func TestCmd(t *testing.T) {
	BeforeSuite(func() {
		log.Logger.ExitFunc = func(int) { fatal = true }

		loggerHook = test.NewGlobal()
		log.Logger.AddHook(loggerHook)
	})
	AfterSuite(func() {
		log.Logger.ExitFunc = nil
		loggerHook.Reset()
	})
	RegisterFailHandler(Fail)
	RunSpecs(t, "Command Suite")
}
