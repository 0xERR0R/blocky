package querylog

import (
	"time"
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
}

type Writer interface {
	Write(entry *LogEntry)
	CleanUp()
}
