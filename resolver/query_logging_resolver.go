package resolver

import (
	"blocky/config"
	"blocky/util"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	cleanUpRunPeriod           = 12 * time.Hour
	queryLoggingResolverPrefix = "query_logging_resolver"
	logChanCap                 = 1000
)

// QueryLoggingResolver writes query information (question, answer, duration, ...) into
// log file or as log entry (if log directory is not configured)
type QueryLoggingResolver struct {
	NextResolver
	logDir           string
	perClient        bool
	logRetentionDays uint64
	logChan          chan *queryLogEntry
}

type queryLogEntry struct {
	request    *Request
	response   *Response
	start      time.Time
	durationMs int64
	logger     *logrus.Entry
}

func NewQueryLoggingResolver(cfg config.QueryLogConfig) ChainedResolver {
	if _, err := os.Stat(cfg.Dir); cfg.Dir != "" && err != nil && os.IsNotExist(err) {
		logger(queryLoggingResolverPrefix).Fatalf("query log directory '%s' does not exist or is not writable", cfg.Dir)
	}

	logChan := make(chan *queryLogEntry, logChanCap)

	resolver := QueryLoggingResolver{
		logDir:           cfg.Dir,
		perClient:        cfg.PerClient,
		logRetentionDays: cfg.LogRetentionDays,
		logChan:          logChan,
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

// deletes old log files
func (r *QueryLoggingResolver) doCleanUp() {
	logger := logger(queryLoggingResolverPrefix)

	logger.Trace("starting clean up")

	files, err := ioutil.ReadDir(r.logDir)
	if err != nil {
		logger.WithField("log_dir", r.logDir).Error("can't list log directory: ", err)
	}

	// search for log files, which names starts with date
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".log") && len(f.Name()) > 10 {
			t, err := time.Parse("2006-01-02", f.Name()[:10])
			if err == nil {
				differenceDays := uint64(time.Since(t).Hours() / 24)
				if r.logRetentionDays > 0 && differenceDays > r.logRetentionDays {
					logger.WithFields(logrus.Fields{
						"file":             f.Name(),
						"ageInDays":        differenceDays,
						"logRetentionDays": r.logRetentionDays,
					}).Info("existing log file is older than retention time and will be deleted")

					err := os.Remove(filepath.Join(r.logDir, f.Name()))
					if err != nil {
						logger.WithField("file", f.Name()).Error("can't remove file: ", err)
					}
				}
			}
		}
	}
}

func (r *QueryLoggingResolver) Resolve(request *Request) (*Response, error) {
	logger := withPrefix(request.Log, queryLoggingResolverPrefix)

	start := time.Now()

	resp, err := r.next.Resolve(request)

	duration := time.Since(start).Milliseconds()

	if err == nil {
		select {
		case r.logChan <- &queryLogEntry{
			request:    request,
			response:   resp,
			start:      start,
			durationMs: duration,
			logger:     logger}:
		default:
			logger.Error("query log writer is too slow, log entry will be dropped")
		}
	}

	return resp, err
}

// write entry: if log directory is configured, write to log file
func (r *QueryLoggingResolver) writeLog() {
	for logEntry := range r.logChan {
		if r.logDir != "" {
			var clientPrefix string

			start := time.Now()

			dateString := logEntry.start.Format("2006-01-02")

			if r.perClient {
				clientPrefix = strings.Join(logEntry.request.ClientNames, "-")
			} else {
				clientPrefix = "ALL"
			}

			fileName := fmt.Sprintf("%s_%s.log", dateString, escape(clientPrefix))
			writePath := filepath.Join(r.logDir, fileName)

			file, err := os.OpenFile(writePath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)

			if err != nil {
				logEntry.logger.WithField("file_name", writePath).Error("can't create/open file", err)
			} else {
				writer := createCsvWriter(file)

				err := writer.Write(createQueryLogRow(logEntry))
				if err != nil {
					logEntry.logger.WithField("file_name", writePath).Error("can't write to file", err)
				}
				writer.Flush()

				_ = file.Close()
			}

			halfCap := cap(r.logChan) / 2

			// if log channel is > 50% full, this could be a problem with slow writer (external storage over network etc.)
			if len(r.logChan) > halfCap {
				logEntry.logger.WithField("channel_len",
					len(r.logChan)).Warnf("query log writer is too slow, write duration: %d ms", time.Since(start).Milliseconds())
			}
		} else {
			logEntry.logger.WithFields(
				logrus.Fields{
					"response_reason": logEntry.response.Reason,
					"response_code":   dns.RcodeToString[logEntry.response.Res.Rcode],
					"answer":          util.AnswerToString(logEntry.response.Res.Answer),
					"duration_ms":     logEntry.durationMs,
				},
			).Infof("query resolved")
		}
	}
}

func escape(file string) string {
	reg := regexp.MustCompile("[^a-zA-Z0-9-_]+")
	return reg.ReplaceAllString(file, "_")
}

func createCsvWriter(file io.Writer) *csv.Writer {
	writer := csv.NewWriter(file)
	writer.Comma = '\t'

	return writer
}

func createQueryLogRow(logEntry *queryLogEntry) []string {
	request := logEntry.request
	response := logEntry.response

	return []string{
		logEntry.start.Format("2006-01-02 15:04:05"),
		request.ClientIP.String(),
		strings.Join(request.ClientNames, "; "),
		fmt.Sprintf("%d", logEntry.durationMs),
		response.Reason,
		util.QuestionToString(request.Req.Question),
		util.AnswerToString(response.Res.Answer),
		dns.RcodeToString[response.Res.Rcode],
	}
}

func (r *QueryLoggingResolver) Configuration() (result []string) {
	if r.logDir != "" {
		result = append(result, fmt.Sprintf("logDir= \"%s\"", r.logDir))
		result = append(result, fmt.Sprintf("perClient = %t", r.perClient))
		result = append(result, fmt.Sprintf("logRetentionDays= %d", r.logRetentionDays))

		if r.logRetentionDays == 0 {
			result = append(result, "log cleanup deactivated")
		}
	} else {
		result = []string{"deactivated"}
	}

	return
}
