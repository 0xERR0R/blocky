package log

import (
	"github.com/0xERR0R/blocky/instanceid"
	log "github.com/sirupsen/logrus"
)

type instanceIDLogger struct {
	formatter log.Formatter
}

func (l instanceIDLogger) Format(entry *log.Entry) ([]byte, error) {
	entry.Data["instanceId"] = instanceid.String()
	return l.formatter.Format(entry)
}
