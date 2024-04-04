package querylog

import (
	"reflect"
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"
	"github.com/sirupsen/logrus"
)

const loggerPrefixLoggerWriter = "queryLog"

type LoggerWriter struct {
	logger *logrus.Entry
}

func NewLoggerWriter() *LoggerWriter {
	return &LoggerWriter{logger: log.PrefixedLog(loggerPrefixLoggerWriter)}
}

func (d *LoggerWriter) Write(entry *LogEntry) {
	fields := LogEntryFields(entry)

	d.logger.WithFields(fields).Infof("query resolved")
}

func (d *LoggerWriter) CleanUp() {
	// Nothing to do
}

func LogEntryFields(entry *LogEntry) logrus.Fields {
	return withoutZeroes(logrus.Fields{
		"client_ip":       entry.ClientIP,
		"client_names":    strings.Join(entry.ClientNames, "; "),
		"response_reason": entry.ResponseReason,
		"response_type":   entry.ResponseType,
		"response_code":   entry.ResponseCode,
		"question_name":   entry.QuestionName,
		"question_type":   entry.QuestionType,
		"answer":          entry.Answer,
		"duration_ms":     entry.DurationMs,
		"hostname":        util.HostnameString(),
	})
}

func withoutZeroes(fields logrus.Fields) logrus.Fields {
	for k, v := range fields {
		if reflect.ValueOf(v).IsZero() {
			delete(fields, k)
		}
	}

	return fields
}
