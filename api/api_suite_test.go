package api_test

import (
	"blocky/log"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestResolver(t *testing.T) {
	log.NewLogger("Warn", "text")
	RegisterFailHandler(Fail)
	RunSpecs(t, "API Suite")
}
