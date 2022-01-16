package log

import (
	log "github.com/sirupsen/logrus"
)

type instanceIdLogger struct {
	instanceId string
	formatter  log.Formatter
}

func (l instanceIdLogger) Format(entry *log.Entry) ([]byte, error) {
	entry.Data["instanceId"] = l.instanceId
	return l.formatter.Format(entry)
}
