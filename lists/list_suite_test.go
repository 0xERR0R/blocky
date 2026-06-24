package lists

import (
	"testing"

	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	log.ConfigureForTest(GinkgoWriter)
})

func TestLists(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Lists Suite")
}
