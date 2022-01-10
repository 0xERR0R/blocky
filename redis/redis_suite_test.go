package redis

import (
	"testing"

	. "github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestRedisClient(t *testing.T) {
	ConfigureLogger(LevelFatal, FormatTypeText, true)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Redis Suite")
}
