package cmd

import (
	"errors"
	"os"
	"slices"
	"syscall"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
)

func TestServeLifecycleOnSIGTERM(t *testing.T) {
	stopErr := errors.New("shutdown failed")
	for _, tc := range []struct {
		name    string
		ready   bool
		stopErr error
		want    []string
	}{
		{"already ready", true, nil, []string{"service started", "service stopped"}},
		{"not ready", false, nil, []string{"service stopped"}},
		{"shutdown fails", true, stopErr, []string{"service started"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready := make(chan struct{})
			if tc.ready {
				close(ready)
			}
			// Both select cases can win when SIGTERM and readiness are pending.
			for range 32 {
				signals := make(chan os.Signal, 1)
				signals <- syscall.SIGTERM
				logger, hook := test.NewNullLogger()
				calls := 0
				err := waitForShutdown(ready, signals, nil, logger.WithField("version", "test"), func() error {
					calls++
					return tc.stopErr
				})
				if calls != 1 || !errors.Is(err, tc.stopErr) {
					t.Fatalf("shutdown called %d times; returned %v, want %v", calls, err, tc.stopErr)
				}
				var got []string
				for _, entry := range hook.AllEntries() {
					got = append(got, entry.Message)
				}
				if !slices.Equal(got, tc.want) {
					t.Fatalf("lifecycle records = %q, want %q", got, tc.want)
				}
			}
		})
	}
}
