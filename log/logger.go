package log

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names

import (
	"io"
	"strings"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

// Logger is the global logging instance
// nolint:gochecknoglobals
var logger *logrus.Logger

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

// nolint:gochecknoinits
func init() {
	logger = logrus.New()

	ConfigureLogger(LevelInfo, FormatTypeText, true)
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
func ConfigureLogger(logLevel Level, formatType FormatType, logTimestamp bool) {
	if level, err := logrus.ParseLevel(logLevel.String()); err != nil {
		logger.Fatalf("invalid log level %s %v", logLevel, err)
	} else {
		logger.SetLevel(level)
	}

	switch formatType {
	case FormatTypeText:
		logFormatter := &prefixed.TextFormatter{
			TimestampFormat:  "2006-01-02 15:04:05",
			FullTimestamp:    true,
			ForceFormatting:  true,
			ForceColors:      false,
			QuoteEmptyFields: true,
			DisableTimestamp: !logTimestamp}

		logFormatter.SetColorScheme(&prefixed.ColorScheme{
			PrefixStyle:    "blue+b",
			TimestampStyle: "white+h",
		})

		logger.SetFormatter(logFormatter)

	case FormatTypeJson:
		logger.SetFormatter(&logrus.JSONFormatter{})
	}
}

// Silence disables the logger output
func Silence() {
	logger.Out = io.Discard
}
