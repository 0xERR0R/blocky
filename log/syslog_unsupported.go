//go:build windows || plan9

package log

import (
	"errors"
)

// newSyslogWriter reports that this platform has no syslog.
func newSyslogWriter(SyslogConfig) (syslogOutput, error) {
	return nil, errors.New("syslog is not available on this platform")
}
