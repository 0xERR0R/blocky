package prefetching_test

import (
	"testing"

	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	log.Silence()
}

func TestCache(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Expiration cache suite")
}
