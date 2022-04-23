package util

import (
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLists(t *testing.T) {
	log.Silence()
	RegisterFailHandler(Fail)
	RunSpecs(t, "Util Suite")
}
