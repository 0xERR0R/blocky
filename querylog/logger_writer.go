package querylog

import (
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const loggerPrefixLoggerWriter = "queryLog"

type LoggerWriter struct {
	logger *logrus.Entry
}

func NewLoggerWriter() *LoggerWriter {
	return &LoggerWriter{logger: log.PrefixedLog(loggerPrefixLoggerWriter)}
}

func (d *LoggerWriter) Write(entry *Entry) {
	d.logger.WithFields(
		logrus.Fields{
			"client_ip":       entry.Request.ClientIP,
			"client_names":    strings.Join(entry.Request.ClientNames, "; "),
			"response_reason": entry.Response.Reason,
			"question":        util.QuestionToString(entry.Request.Req.Question),
			"response_code":   dns.RcodeToString[entry.Response.Res.Rcode],
			"answer":          util.AnswerToString(entry.Response.Res.Answer),
			"duration_ms":     entry.DurationMs,
		},
	).Infof("query resolved")
}

func (d *LoggerWriter) CleanUp() {
	// Nothing to do
}
