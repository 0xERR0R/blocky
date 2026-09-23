//go:build windows || plan9

package log

import (
	"errors"

	"github.com/sirupsen/logrus"
)

// newSyslogHook reports that this platform has no syslog.
func newSyslogHook(SyslogConfig, logrus.Formatter) (logrus.Hook, error) {
	return nil, errors.New("syslog is not available on this platform")
}
