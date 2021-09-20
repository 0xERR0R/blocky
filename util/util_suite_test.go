package util

import (
	"testing"

	. "github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLists(t *testing.T) {
	ConfigureLogger(LevelError, FormatTypeText, true)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Util Suite")
}
