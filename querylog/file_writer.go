package querylog

import (
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const loggerPrefixFileWriter = "fileQueryLogWriter"

var validFilePattern = regexp.MustCompile("[^a-zA-Z0-9-_]+")

type FileWriter struct {
	target           string
	perClient        bool
	logRetentionDays uint64
}

func NewCSVWriter(target string, perClient bool, logRetentionDays uint64) (*FileWriter, error) {
	if _, err := os.Stat(target); target != "" && err != nil && os.IsNotExist(err) {
		return nil, fmt.Errorf("query log directory '%s' does not exist or is not writable", target)
	}

	return &FileWriter{
		target:           target,
		perClient:        perClient,
		logRetentionDays: logRetentionDays,
	}, nil
}

func (d *FileWriter) Write(entry *LogEntry) {
	var clientPrefix string

	dateString := entry.Start.Format("2006-01-02")

	if d.perClient {
		clientPrefix = strings.Join(entry.Request.ClientNames, "-")
	} else {
		clientPrefix = "ALL"
	}

	fileName := fmt.Sprintf("%s_%s.log", dateString, escape(clientPrefix))
	writePath := filepath.Join(d.target, fileName)

	file, err := os.OpenFile(writePath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)

	util.LogOnErrorWithEntry(log.PrefixedLog(loggerPrefixFileWriter).WithField("file_name", writePath),
		"can't create/open file", err)

	if err == nil {
		writer := createCsvWriter(file)

		err := writer.Write(createQueryLogRow(entry))
		util.LogOnErrorWithEntry(log.PrefixedLog(loggerPrefixFileWriter).WithField("file_name", writePath),
			"can't write to file", err)
		writer.Flush()

		_ = file.Close()
	}
}

// CleanUp deletes old log files
func (d *FileWriter) CleanUp() {
	const hoursPerDay = 24

	logger := log.PrefixedLog(loggerPrefixFileWriter)

	logger.Trace("starting clean up")

	files, err := ioutil.ReadDir(d.target)

	util.LogOnErrorWithEntry(logger.WithField("target", d.target), "can't list log directory: ", err)

	// search for log files, which names starts with date
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".log") && len(f.Name()) > 10 {
			t, err := time.Parse("2006-01-02", f.Name()[:10])
			if err == nil {
				differenceDays := uint64(time.Since(t).Hours() / hoursPerDay)
				if d.logRetentionDays > 0 && differenceDays > d.logRetentionDays {
					logger.WithFields(logrus.Fields{
						"file":             f.Name(),
						"ageInDays":        differenceDays,
						"logRetentionDays": d.logRetentionDays,
					}).Info("existing log file is older than retention time and will be deleted")

					err := os.Remove(filepath.Join(d.target, f.Name()))
					util.LogOnErrorWithEntry(logger.WithField("file", f.Name()), "can't remove file: ", err)
				}
			}
		}
	}
}

func createQueryLogRow(logEntry *LogEntry) []string {
	request := logEntry.Request
	response := logEntry.Response

	return []string{
		logEntry.Start.Format("2006-01-02 15:04:05"),
		request.ClientIP.String(),
		strings.Join(request.ClientNames, "; "),
		fmt.Sprintf("%d", logEntry.DurationMs),
		response.Reason,
		util.QuestionToString(request.Req.Question),
		util.AnswerToString(response.Res.Answer),
		dns.RcodeToString[response.Res.Rcode],
	}
}

func createCsvWriter(file io.Writer) *csv.Writer {
	writer := csv.NewWriter(file)
	writer.Comma = '\t'

	return writer
}

func escape(file string) string {
	return validFilePattern.ReplaceAllString(file, "_")
}
