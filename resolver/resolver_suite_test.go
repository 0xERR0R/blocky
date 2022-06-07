package resolver_test

import (
	"context"
	"testing"

	"github.com/0xERR0R/blocky/log"

	"github.com/go-redis/redis/v8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestResolver(t *testing.T) {
	log.Silence()
	redis.SetLogger(NoLogs{})
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resolver Suite")
}

type NoLogs struct{}

func (l NoLogs) Printf(_ context.Context, _ string, _ ...interface{}) {}
