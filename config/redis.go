package config

// Redis configuration for the redis connection
type Redis struct {
	Address            string   `yaml:"address"`
	Username           string   `yaml:"username" default:""`
	Password           string   `yaml:"password" default:""`
	Database           int      `yaml:"database" default:"0"`
	Required           bool     `yaml:"required" default:"false"`
	ConnectionAttempts int      `yaml:"connectionAttempts" default:"3"`
	ConnectionCooldown Duration `yaml:"connectionCooldown" default:"1s"`
	SentinelUsername   string   `yaml:"sentinelUsername" default:""`
	SentinelPassword   string   `yaml:"sentinelPassword" default:""`
	SentinelAddresses  []string `yaml:"sentinelAddresses"`
}
