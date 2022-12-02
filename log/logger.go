package log

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names

import (
	"io"
	"strings"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

// Logger is the global logging instance
//
//nolint:gochecknoglobals
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

// Config defines all logging configurations
type Config struct {
	Level     Level      `yaml:"level" default:"info"`
	Format    FormatType `yaml:"format" default:"text"`
	Privacy   bool       `yaml:"privacy" default:"false"`
	Timestamp bool       `yaml:"timestamp" default:"true"`
}

//nolint:gochecknoinits
func init() {
	logger = logrus.New()

	defaultConfig := &Config{
		Level:     LevelInfo,
		Format:    FormatTypeText,
		Privacy:   false,
		Timestamp: true,
	}

	ConfigureLogger(defaultConfig)
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
func ConfigureLogger(cfg *Config) {
	if level, err := logrus.ParseLevel(cfg.Level.String()); err != nil {
		logger.Fatalf("invalid log level %s %v", cfg.Level, err)
	} else {
		logger.SetLevel(level)
	}

	switch cfg.Format {
	case FormatTypeText:
		logFormatter := &prefixed.TextFormatter{
			TimestampFormat:  "2006-01-02 15:04:05",
			FullTimestamp:    true,
			ForceFormatting:  true,
			ForceColors:      false,
			QuoteEmptyFields: true,
			DisableTimestamp: !cfg.Timestamp}

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
