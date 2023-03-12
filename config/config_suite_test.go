package config

import (
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var (
	logger *logrus.Entry
	hook   *log.MockLoggerHook
)

func TestConfig(t *testing.T) {
	log.Silence()
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}

func suiteBeforeEach() {
	BeforeEach(func() {
		logger, hook = log.NewMockEntry()
	})
}
