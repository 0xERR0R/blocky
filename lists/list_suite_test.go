package lists

import (
	"blocky/log"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLists(t *testing.T) {
	log.NewLogger("Warn", "text")
	RegisterFailHandler(Fail)
	RunSpecs(t, "Lists Suite")
}
