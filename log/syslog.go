//go:build !windows && !plan9

package log

import (
	"fmt"
	"log/syslog"
	"maps"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
)

// Facilities a DNS server can sensibly claim: the system daemon facility and the
// eight reserved for local use.
//
//nolint:gochecknoglobals
var syslogFacilities = map[string]syslog.Priority{
	"daemon": syslog.LOG_DAEMON,
	"user":   syslog.LOG_USER,
	"local0": syslog.LOG_LOCAL0,
	"local1": syslog.LOG_LOCAL1,
	"local2": syslog.LOG_LOCAL2,
	"local3": syslog.LOG_LOCAL3,
	"local4": syslog.LOG_LOCAL4,
	"local5": syslog.LOG_LOCAL5,
	"local6": syslog.LOG_LOCAL6,
	"local7": syslog.LOG_LOCAL7,
}

// newSyslogHook connects to syslog and returns a hook writing each entry at the
// priority matching its level.
func newSyslogHook(cfg SyslogConfig, formatter logrus.Formatter) (logrus.Hook, error) {
	facility, found := syslogFacilities[strings.ToLower(cfg.Facility)]
	if !found {
		names := slices.Sorted(maps.Keys(syslogFacilities))

		return nil, fmt.Errorf("invalid syslog facility '%s', try one of: %s",
			cfg.Facility, strings.Join(names, ", "))
	}

	// an empty network dials the local syslog socket
	writer, err := syslog.Dial(cfg.Network, cfg.Address, facility, cfg.Tag)
	if err != nil {
		return nil, fmt.Errorf("can't connect to syslog: %w", err)
	}

	return &syslogHook{writer: writer, formatter: formatter}, nil
}

type syslogHook struct {
	writer    *syslog.Writer
	formatter logrus.Formatter
}

// Levels implements `logrus.Hook`.
func (h *syslogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire implements `logrus.Hook`.
func (h *syslogHook) Fire(entry *logrus.Entry) error {
	line, err := h.formatter.Format(entry)
	if err != nil {
		return err
	}

	write := h.writeFunc(entry.Level)

	// a syslog record is a single line, so a multi-line entry becomes one record
	// per line rather than one record containing newlines
	for message := range strings.SplitSeq(strings.TrimRight(string(line), "\n"), "\n") {
		if err := write(message); err != nil {
			return err
		}
	}

	return nil
}

func (h *syslogHook) writeFunc(level logrus.Level) func(string) error {
	switch level {
	case logrus.PanicLevel, logrus.FatalLevel:
		return h.writer.Crit
	case logrus.ErrorLevel:
		return h.writer.Err
	case logrus.WarnLevel:
		return h.writer.Warning
	case logrus.InfoLevel:
		return h.writer.Info
	case logrus.DebugLevel, logrus.TraceLevel:
		return h.writer.Debug
	default:
		return h.writer.Info
	}
}
