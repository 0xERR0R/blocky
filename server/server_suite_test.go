package server

import (
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDNSServer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Server Suite")
}

// capturedLog is the handle returned by installLogHook.
type capturedLog struct {
	rec     *log.Recorder
	restore func()
}

// installLogHook swaps in a Recorder on the global logger so a test can
// assert on emitted log messages. The returned handle's uninstall() must be
// called (typically via DeferCleanup) to restore the previous logger.
func installLogHook() *capturedLog {
	rec, restore := log.CaptureGlobal()

	return &capturedLog{rec: rec, restore: restore}
}

func (c *capturedLog) messages() []string { return c.rec.Messages() }
func (c *capturedLog) uninstall()         { c.restore() }
