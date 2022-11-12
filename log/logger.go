package log

import (
	"io"
	"os"
	"strings"

	"github.com/0xERR0R/blocky/logconfig"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

// Logger is the global logging instance
// nolint:gochecknoglobals
var logger *logrus.Logger

// nolint:gochecknoinits
func init() {
	logger = logrus.New()

	lc := logconfig.Config{
		Level:     logconfig.LevelInfo,
		Format:    logconfig.FormatTypeText,
		Timestamp: true,
	}

	ConfigureLogger(lc)
}

type hostnameFormatter struct {
	hostname  string
	formatter logrus.Formatter
}

func (l hostnameFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	newentry := *entry
	newentry.Data["host"] = l.hostname

	return l.formatter.Format(&newentry)
}

// Log returns the global logger
func Log() *logrus.Logger {
	return logger
}

// PrefixedLog return the global logger with prefix
func PrefixedLog(prefix string) *logrus.Entry {
	return logger.WithField("prefix", prefix)
}

// EscapeInput removes line breaks from input
func EscapeInput(input string) string {
	result := strings.ReplaceAll(input, "\n", "")
	result = strings.ReplaceAll(result, "\r", "")

	return result
}

// ConfigureLogger applies configuration to the global logger
func ConfigureLogger(lc logconfig.Config) {
	if level, err := logrus.ParseLevel(lc.Level.String()); err != nil {
		logger.Fatalf("invalid log level %s %v", lc.Level, err)
	} else {
		logger.SetLevel(level)
	}

	var formatter logrus.Formatter

	switch lc.Format {
	case logconfig.FormatTypeText:
		logFormatter := &prefixed.TextFormatter{
			TimestampFormat:  "2006-01-02 15:04:05",
			FullTimestamp:    true,
			ForceFormatting:  true,
			ForceColors:      false,
			QuoteEmptyFields: true,
			DisableTimestamp: !lc.Timestamp,
		}

		logFormatter.SetColorScheme(&prefixed.ColorScheme{
			PrefixStyle:    "blue+b",
			TimestampStyle: "white+h",
		})

		formatter = logFormatter

	case logconfig.FormatTypeJson:
		formatter = &logrus.JSONFormatter{}
	}

	if lc.Hostname {
		if hn, err := os.Hostname(); err == nil {
			logger.SetFormatter(hostnameFormatter{
				hostname:  hn,
				formatter: formatter,
			})

			return
		}
	}

	logger.SetFormatter(formatter)
}

// Silence disables the logger output
func Silence() {
	logger.Out = io.Discard
}
