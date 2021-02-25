package server

import (
	. "blocky/log"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestDNSServer(t *testing.T) {
	ConfigureLogger("Warn", "text")
	RegisterFailHandler(Fail)
	RunSpecs(t, "Server Suite")
}
