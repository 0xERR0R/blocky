package log

import (
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

// Logger is the global logging instance
// nolint:gochecknoglobals
var logger *logrus.Logger

const (
	// CfgLogFormatText logging as text
	CfgLogFormatText = "text"

	// CfgLogFormatJSON as JSON
	CfgLogFormatJSON = "json"
)

// nolint:gochecknoinits
func init() {
	logger = logrus.New()

	ConfigureLogger("info", "text", true)
}

// Log returns the global logger
func Log() *logrus.Logger {
	return logger
}

// PrefixedLog return the global logger with prefix
func PrefixedLog(prefix string) *logrus.Entry {
	return logger.WithField("prefix", prefix)
}

// ConfigureLogger applies configuration to the global logger
func ConfigureLogger(logLevel, logFormat string, logTimestamp bool) {
	if len(logLevel) == 0 {
		logLevel = "info"
	}

	if level, err := logrus.ParseLevel(logLevel); err != nil {
		logger.Fatalf("invalid log level %s %v", logLevel, err)
	} else {
		logger.SetLevel(level)
	}

	if logFormat == CfgLogFormatText {
		logFormatter := &prefixed.TextFormatter{
			TimestampFormat:  "2006-01-02 15:04:05",
			FullTimestamp:    true,
			ForceFormatting:  true,
			ForceColors:      true,
			QuoteEmptyFields: true,
			DisableTimestamp: !logTimestamp}

		logFormatter.SetColorScheme(&prefixed.ColorScheme{
			PrefixStyle:    "blue+b",
			TimestampStyle: "white+h",
		})

		logger.SetFormatter(logFormatter)
	}

	if logFormat == CfgLogFormatJSON {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}
}
