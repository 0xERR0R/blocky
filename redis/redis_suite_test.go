package redis

import (
	"context"
	"testing"

	"github.com/0xERR0R/blocky/log"
	"github.com/go-redis/redis/v8"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRedisClient(t *testing.T) {
	log.Silence()
	redis.SetLogger(NoLogs{})
	RegisterFailHandler(Fail)
	RunSpecs(t, "Redis Suite")
}

type NoLogs struct{}

func (l NoLogs) Printf(context.Context, string, ...interface{}) {}
