package config

import (
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	log.Silence()
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}
