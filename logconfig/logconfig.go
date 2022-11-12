package logconfig

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names

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
