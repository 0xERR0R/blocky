package querylog

import (
	"testing"

	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestResolver(t *testing.T) {
	log.Silence()
	RegisterFailHandler(Fail)
	RunSpecs(t, "Querylog Suite")
}
