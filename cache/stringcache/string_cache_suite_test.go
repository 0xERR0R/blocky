package stringcache_test

import (
	"testing"

	. "github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCache(t *testing.T) {
	ConfigureLogger(LevelFatal, FormatTypeText, true)
	RegisterFailHandler(Fail)
	RunSpecs(t, "String cache suite")
}
