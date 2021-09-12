package resolver

import (
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/querylog"
)

const (
	cleanUpRunPeriod           = 12 * time.Hour
	queryLoggingResolverPrefix = "query_logging_resolver"
	logChanCap                 = 1000
)

// QueryLoggingResolver writes query information (question, answer, duration, ...)
type QueryLoggingResolver struct {
	NextResolver
	target           string
	logRetentionDays uint64
	logChan          chan *querylog.Entry
	writer           querylog.Writer
}

// NewQueryLoggingResolver returns a new resolver instance
func NewQueryLoggingResolver(cfg config.QueryLogConfig) ChainedResolver {
	var writer querylog.Writer

	switch cfg.Type {
	case config.QueryLogTypeCsv:
		writer = querylog.NewCSVWriter(cfg.Target, false, cfg.LogRetentionDays)
	case config.QueryLogTypeCsvClient:
		writer = querylog.NewCSVWriter(cfg.Target, true, cfg.LogRetentionDays)
	case config.QueryLogTypeMysql:
		writer = querylog.NewDatabaseWriter(cfg.Target, cfg.LogRetentionDays, 30*time.Second)
	case config.QueryLogTypeNone:
		writer = querylog.NewLoggerWriter()
	}

	logChan := make(chan *querylog.Entry, logChanCap)

	resolver := QueryLoggingResolver{
		target:           cfg.Target,
		logRetentionDays: cfg.LogRetentionDays,
		logChan:          logChan,
		writer:           writer,
	}

	go resolver.writeLog()

	if cfg.LogRetentionDays > 0 {
		go resolver.periodicCleanUp()
	}

	return &resolver
}

// triggers periodically cleanup of old log files
func (r *QueryLoggingResolver) periodicCleanUp() {
	ticker := time.NewTicker(cleanUpRunPeriod)
	defer ticker.Stop()

	for {
		<-ticker.C
		r.doCleanUp()
	}
}

func (r *QueryLoggingResolver) doCleanUp() {
	r.writer.CleanUp()
}

// Resolve logs the query, duration and the result
func (r *QueryLoggingResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := withPrefix(request.Log, queryLoggingResolverPrefix)

	start := time.Now()

	resp, err := r.next.Resolve(request)

	duration := time.Since(start).Milliseconds()

	if err == nil {
		select {
		case r.logChan <- &querylog.Entry{
			Request:    request,
			Response:   resp,
			Start:      start,
			DurationMs: duration}:
		default:
			logger.Error("query log writer is too slow, log entry will be dropped")
		}
	}

	return resp, err
}

// write entry: if log directory is configured, write to log file
func (r *QueryLoggingResolver) writeLog() {
	for logEntry := range r.logChan {
		start := time.Now()

		r.writer.Write(logEntry)

		halfCap := cap(r.logChan) / 2

		// if log channel is > 50% full, this could be a problem with slow writer (external storage over network etc.)
		if len(r.logChan) > halfCap {
			logger(queryLoggingResolverPrefix).WithField("channel_len",
				len(r.logChan)).Warnf("query log writer is too slow, write duration: %d ms", time.Since(start).Milliseconds())
		}
	}
}

// Configuration returns the current resolver configuration
func (r *QueryLoggingResolver) Configuration() (result []string) {
	if r.target != "" {
		result = append(result, fmt.Sprintf("target: \"%s\"", r.target))
		result = append(result, fmt.Sprintf("logRetentionDays: %d", r.logRetentionDays))

		if r.logRetentionDays == 0 {
			result = append(result, "log cleanup deactivated")
		}
	} else {
		result = []string{"deactivated"}
	}

	return
}
