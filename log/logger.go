package log

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

// FormatType format for logging ENUM(
// text // logging as text
// json // JSON format
// )
type FormatType int

// Level log level ENUM(
// info
// trace
// debug
// warn
// error
// fatal
// )
type Level int

type Config struct {
	Level     Level      `yaml:"level" default:"info"`
	Format    FormatType `yaml:"format" default:"text"`
	Privacy   bool       `yaml:"privacy" default:"false"`
	Timestamp bool       `yaml:"timestamp" default:"true"`
	Hostname  bool       `yaml:"hostname" default:"false"`
}

// Logger is the global logging instance
// nolint:gochecknoglobals
var logger *logrus.Logger

// nolint:gochecknoinits
func init() {
	logger = logrus.New()

	lc := Config{
		Level:     LevelInfo,
		Format:    FormatTypeText,
		Timestamp: true,
	}

	ConfigureLogger(lc)
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
func ConfigureLogger(lc Config) {
	if level, err := logrus.ParseLevel(lc.Level.String()); err != nil {
		logger.Fatalf("invalid log level %s %v", lc.Level, err)
	} else {
		logger.SetLevel(level)
	}

	var baseFormatter logrus.Formatter

	switch lc.Format {
	case FormatTypeText:
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

		baseFormatter = logFormatter

	case FormatTypeJson:
		baseFormatter = &logrus.JSONFormatter{}
	}

	var newFormatter logrus.Formatter

	if hn, err := getHostname(); err == nil && lc.Hostname {
		newFormatter = hostnameFormatter{
			hostname:  hn,
			formatter: baseFormatter,
		}
	} else {
		newFormatter = baseFormatter
	}

	logger.SetFormatter(newFormatter)
}

// Silence disables the logger output
func Silence() {
	logger.Out = io.Discard
}

type hostnameFormatter struct {
	hostname  string
	formatter logrus.Formatter
}

func (l hostnameFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	newentry := *entry
	newentry.Data["hostname"] = l.hostname

	return l.formatter.Format(&newentry)
}

func getHostname() (string, error) {
	if hn, err := os.ReadFile("/etc/hostname"); err == nil {
		return strings.TrimSpace(string(hn)), nil
	}

	if hn, err := os.Hostname(); err == nil {
		return hn, nil
	}

	return "", errors.New("hostname couldn't be determined")
}
