package cmd

import (
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus/hooks/test"
)

var (
	fatal      bool
	loggerHook *test.Hook
)

func TestCmd(t *testing.T) {
	log.Silence()
	BeforeSuite(func() {
		log.Log().ExitFunc = func(int) { fatal = true }

		loggerHook = test.NewGlobal()
		log.Log().AddHook(loggerHook)
	})
	AfterSuite(func() {
		log.Log().ExitFunc = nil
		loggerHook.Reset()
	})
	RegisterFailHandler(Fail)
	RunSpecs(t, "Command Suite")
}
