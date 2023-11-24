package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/0xERR0R/blocky/helpertest"
	"github.com/avast/retry-go/v4"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

func init() {
	log.Silence()
}

func TestLists(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "e2e Suite", Label("e2e"))
}

var (
	network testcontainers.Network
	tmpDir  *helpertest.TmpFolder
)

var _ = BeforeSuite(func(ctx context.Context) {
	var err error

	network, err = testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{
			Name:           NetworkName,
			CheckDuplicate: false,
			Attachable:     true,
		},
	})

	Expect(err).Should(Succeed())

	DeferCleanup(func(ctx context.Context) {
		err := retry.Do(
			func() error {
				return network.Remove(ctx)
			},
			retry.Attempts(3),
			retry.DelayType(retry.BackOffDelay),
			retry.Delay(time.Second))
		Expect(err).Should(Succeed())
	})

	tmpDir = helpertest.NewTmpFolder("config")

	SetDefaultEventuallyTimeout(5 * time.Second)
})
