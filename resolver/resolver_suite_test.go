package resolver

import (
	"testing"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	timeout = 50 * time.Millisecond
)

var defaultUpstreamsConfig config.Upstreams

func init() {
	log.Silence()

	var err error

	defaultUpstreamsConfig, err = config.WithDefaults[config.Upstreams]()
	if err != nil {
		panic(err)
	}

	// Shorter timeout for tests
	defaultUpstreamsConfig.Timeout = config.Duration(timeout)
}

func TestResolver(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resolver Suite")
}
