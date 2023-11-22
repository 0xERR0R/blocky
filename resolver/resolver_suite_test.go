package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/go-redis/redis/v8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	timeout = 50 * time.Millisecond
)

var defaultUpstreamsConfig config.Upstreams

func init() {
	log.Silence()
	redis.SetLogger(NoLogs{})

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

type NoLogs struct{}

func (l NoLogs) Printf(_ context.Context, _ string, _ ...interface{}) {}
