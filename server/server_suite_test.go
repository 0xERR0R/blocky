package server

import (
	"maps"
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	log.Silence()
}

func TestDNSServer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Server Suite")
}

// capturedLog is the handle returned by installLogHook.
type capturedLog struct {
	hook    *log.MockLoggerHook
	restore func()
}

// installLogHook attaches a MockLoggerHook to the global logger so a
// test can assert on emitted log messages. The returned handle's
// uninstall() must be called (typically via DeferCleanup) to restore
// the previous hook set.
func installLogHook() *capturedLog {
	logger := log.Log()
	prevHooks := maps.Clone(logger.Hooks)

	_, hook := log.NewMockEntry()
	logger.AddHook(hook)

	return &capturedLog{
		hook:    hook,
		restore: func() { logger.ReplaceHooks(prevHooks) },
	}
}

func (c *capturedLog) messages() []string { return c.hook.Messages }
func (c *capturedLog) uninstall()         { c.restore() }
