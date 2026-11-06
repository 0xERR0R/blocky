package config

// Pprof contains the config values for the Go profiler (pprof) endpoints
type Pprof struct {
	// If true, serves the Go profiler (pprof) endpoints under /debug on the HTTP(S) listeners.
	Enable bool `default:"true" yaml:"enable"`
}
