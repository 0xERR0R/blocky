package resolver

import (
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/querylog"
	"github.com/avast/retry-go/v4"
)

const (
	cleanUpRunPeriod           = 12 * time.Hour
	queryLoggingResolverPrefix = "query_logging_resolver"
	logChanCap                 = 1000
	defaultFlushPeriod         = 30 * time.Second
)

// QueryLoggingResolver writes query information (question, answer, duration, ...)
type QueryLoggingResolver struct {
	NextResolver
	target           string
	logRetentionDays uint64
	logChan          chan *querylog.LogEntry
	writer           querylog.Writer
	logType          config.QueryLogType
}

// NewQueryLoggingResolver returns a new resolver instance
func NewQueryLoggingResolver(cfg config.QueryLogConfig) ChainedResolver {
	var writer querylog.Writer

	logType := cfg.Type
	err := retry.Do(
		func() error {
			var err error
			switch logType {
			case config.QueryLogTypeCsv:
				writer, err = querylog.NewCSVWriter(cfg.Target, false, cfg.LogRetentionDays)
			case config.QueryLogTypeCsvClient:
				writer, err = querylog.NewCSVWriter(cfg.Target, true, cfg.LogRetentionDays)
			case config.QueryLogTypeMysql:
				writer, err = querylog.NewDatabaseWriter("mysql", cfg.Target, cfg.LogRetentionDays, defaultFlushPeriod)
			case config.QueryLogTypePostgresql:
				writer, err = querylog.NewDatabaseWriter("postgresql", cfg.Target, cfg.LogRetentionDays, defaultFlushPeriod)
			case config.QueryLogTypeConsole:
				writer = querylog.NewLoggerWriter()
			case config.QueryLogTypeNone:
				writer = querylog.NewNoneWriter()
			}

			return err
		},
		retry.Attempts(uint(cfg.CreationAttempts)),
		retry.Delay(time.Duration(cfg.CreationCooldown)),
		retry.OnRetry(func(n uint, err error) {
			logger(queryLoggingResolverPrefix).Warnf("Error occurred on query writer creation, "+
				"retry attempt %d/%d: %v", n+1, cfg.CreationAttempts, err)
		}))

	if err != nil {
		logger(queryLoggingResolverPrefix).Error("can't create query log writer, using console as fallback: ", err)

		writer = querylog.NewLoggerWriter()
		logType = config.QueryLogTypeConsole
	}

	logChan := make(chan *querylog.LogEntry, logChanCap)

	resolver := QueryLoggingResolver{
		target:           cfg.Target,
		logRetentionDays: cfg.LogRetentionDays,
		logChan:          logChan,
		writer:           writer,
		logType:          logType,
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
		case r.logChan <- &querylog.LogEntry{
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

		halfCap := cap(r.logChan) / 2 // nolint:gomnd

		// if log channel is > 50% full, this could be a problem with slow writer (external storage over network etc.)
		if len(r.logChan) > halfCap {
			logger(queryLoggingResolverPrefix).WithField("channel_len",
				len(r.logChan)).Warnf("query log writer is too slow, write duration: %d ms", time.Since(start).Milliseconds())
		}
	}
}

// Configuration returns the current resolver configuration
func (r *QueryLoggingResolver) Configuration() (result []string) {
	result = append(result, fmt.Sprintf("type: \"%s\"", r.logType))
	result = append(result, fmt.Sprintf("target: \"%s\"", r.target))
	result = append(result, fmt.Sprintf("logRetentionDays: %d", r.logRetentionDays))

	return
}
