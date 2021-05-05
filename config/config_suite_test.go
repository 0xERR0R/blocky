package config

import (
	. "blocky/log"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	ConfigureLogger("Warn", "Text", true)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}
