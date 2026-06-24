package config

import (
	"log/slog"
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	logger *slog.Logger
	rec    *log.Recorder
)

var _ = BeforeSuite(func() {
	log.ConfigureForTest(GinkgoWriter)
})

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}

func suiteBeforeEach() {
	BeforeEach(func() {
		logger, rec = log.NewRecorder()
	})
}
