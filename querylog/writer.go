package querylog

import (
	"time"

	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

// DropReason says why a query log entry was dropped instead of written.
type DropReason string

// The reasons a query log entry is dropped.
const (
	DropReasonQueueFull  DropReason = "queue_full"  // the writer fell behind its queue
	DropReasonBufferFull DropReason = "buffer_full" // the database was slow or down for too long
	DropReasonRejected   DropReason = "rejected"    // the database refused the row
	DropReasonShutdown   DropReason = "shutdown"    // not written before blocky stopped
)

//nolint:gochecknoglobals
var entriesDropped = newEntriesDropped()

func newEntriesDropped() *prometheus.CounterVec {
	c := promauto.With(metrics.Reg).NewCounterVec(
		prometheus.CounterOpts{
			Name: "blocky_query_log_entries_dropped_total",
			Help: "Number of query log entries dropped instead of written, by reason",
		},
		[]string{"reason"},
	)

	// Export every series from the start, so a rate or alert works before the first drop.
	reasons := []DropReason{DropReasonQueueFull, DropReasonBufferFull, DropReasonRejected, DropReasonShutdown}
	for _, reason := range reasons {
		c.WithLabelValues(string(reason))
	}

	return c
}

// CountDropped counts n entries dropped for reason.
func CountDropped(reason DropReason, n int) {
	entriesDropped.WithLabelValues(string(reason)).Add(float64(n))
}
