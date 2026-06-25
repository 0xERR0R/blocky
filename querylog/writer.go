package querylog

import (
	"time"

	"github.com/0xERR0R/blocky/model"
)

type LogEntry struct {
	Start          time.Time
	ClientIP       string
	ClientNames    []string
	DurationMs     int64
	ResponseReason string
	ResponseType   string
	ResponseCode   string
	QuestionType   string
	QuestionName   string
	Answer         string
	BlockyInstance string
	QueryWire      []byte
	ResponseWire   []byte
	QueryTime      time.Time
	ResponseTime   time.Time
	SocketProtocol model.RequestProtocol
}

type Writer interface {
	Write(entry *LogEntry)
	CleanUp()
}
