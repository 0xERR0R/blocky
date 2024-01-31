package querylog

import (
	_ "strings"

	"github.com/0xERR0R/blocky/log"
	_ "github.com/0xERR0R/blocky/util"
	"github.com/sirupsen/logrus"
)

const loggerPrefixLoggerWriter = "query"

type LoggerWriter struct {
	logger *logrus.Entry
}

func NewLoggerWriter() *LoggerWriter {
	return &LoggerWriter{logger: log.PrefixedLog(loggerPrefixLoggerWriter)}
}

func (d *LoggerWriter) Write(entry *LogEntry) {
	d.logger.WithFields(
		logrus.Fields{
			"cli_ip":  entry.ClientIP,
			"reason":  entry.ResponseReason,
			"rcode":   entry.ResponseCode,
			"qname":   entry.QuestionName,
			"qtype":   entry.QuestionType,
			"answer":  entry.Answer,
			"time_ms": entry.DurationMs,
		},
	).Infof("")
}

func (d *LoggerWriter) CleanUp() {
	// Nothing to do
}
