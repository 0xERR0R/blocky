package cmd

import (
	"testing"

	. "github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus/hooks/test"
)

var (
	fatal      bool
	loggerHook *test.Hook
)

func TestCmd(t *testing.T) {
	BeforeSuite(func() {
		Log().ExitFunc = func(int) { fatal = true }

		loggerHook = test.NewGlobal()
		Log().AddHook(loggerHook)
	})
	AfterSuite(func() {
		Log().ExitFunc = nil
		loggerHook.Reset()
	})
	RegisterFailHandler(Fail)
	RunSpecs(t, "Command Suite")
}
