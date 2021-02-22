package log

import (
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var Logger *logrus.Logger

const (
	CfgLogFormatText = "text"
	CfgLogFormatJSON = "json"
)

func init() {
	NewLogger("info", "text")
}

func NewLogger(logLevel, logFormat string) {
	if len(logLevel) == 0 {
		logLevel = "info"
	}

	logger := logrus.New()
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
			QuoteEmptyFields: true}

		logFormatter.SetColorScheme(&prefixed.ColorScheme{
			PrefixStyle:    "blue+b",
			TimestampStyle: "white+h",
		})

		logger.SetFormatter(logFormatter)
	}

	if logFormat == CfgLogFormatJSON {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	Logger = logger
}
