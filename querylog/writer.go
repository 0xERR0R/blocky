package querylog

import (
	"time"

	"github.com/0xERR0R/blocky/model"
)

type LogEntry struct {
	Request    *model.Request
	Response   *model.Response
	Start      time.Time
	DurationMs int64
}

type Writer interface {
	Write(entry *LogEntry)
	CleanUp()
}
