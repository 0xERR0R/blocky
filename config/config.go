//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names --values
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"

	"github.com/0xERR0R/blocky/log"
	"github.com/creasty/defaults"
	"gopkg.in/yaml.v2"
)

const (
	udpPort   = 53
	tlsPort   = 853
	httpsPort = 443
)

type Configurable interface {
	// IsEnabled returns true when the receiver is configured.
	IsEnabled() bool

	// LogConfig logs the receiver's configuration.
	//
	// Calling this method when `IsEnabled` returns false is undefined.
	LogConfig(*logrus.Entry)
}

// NetProtocol resolver protocol ENUM(
// tcp+udp // TCP and UDP protocols
// tcp-tls // TCP-TLS protocol
// https // HTTPS protocol
// )
type NetProtocol uint16

// IPVersion represents IP protocol version(s). ENUM(
// dual // IPv4 and IPv6
// v4   // IPv4 only
// v6   // IPv6 only
// )
type IPVersion uint8

func (ipv IPVersion) Net() string {
	switch ipv {
	case IPVersionDual:
		return "ip"
	case IPVersionV4:
		return "ip4"
	case IPVersionV6:
		return "ip6"
	}

	panic(fmt.Errorf("bad value: %s", ipv))
}

func (ipv IPVersion) QTypes() []dns.Type {
	switch ipv {
	case IPVersionDual:
		return []dns.Type{dns.Type(dns.TypeA), dns.Type(dns.TypeAAAA)}
	case IPVersionV4:
		return []dns.Type{dns.Type(dns.TypeA)}
	case IPVersionV6:
		return []dns.Type{dns.Type(dns.TypeAAAA)}
	}

	panic(fmt.Errorf("bad value: %s", ipv))
}

// QueryLogType type of the query log ENUM(
// console // use logger as fallback
// none // no logging
// mysql // MySQL or MariaDB database
// postgresql // PostgreSQL database
// csv // CSV file per day
// csv-client // CSV file per day and client
// )
type QueryLogType int16

// StartStrategyType upstart strategy ENUM(
// blocking // synchronously download blocking lists on startup
// failOnError // synchronously download blocking lists on startup and shutdown on error
// fast // asyncronously download blocking lists on startup
// )
type StartStrategyType uint16

// QueryLogField data field to be logged
// ENUM(clientIP,clientName,responseReason,responseAnswer,question,duration)
type QueryLogField string

//nolint:gochecknoglobals
var netDefaultPort = map[NetProtocol]uint16{
	NetProtocolTcpUdp: udpPort,
	NetProtocolTcpTls: tlsPort,
	NetProtocolHttps:  httpsPort,
}

// ListenConfig is a list of address(es) to listen on
type ListenConfig []string

// UnmarshalText implements `encoding.TextUnmarshaler`.
func (l *ListenConfig) UnmarshalText(data []byte) error {
	addresses := string(data)

	*l = strings.Split(addresses, ",")

	return nil
}

// UnmarshalYAML creates BootstrapDNSConfig from YAML
func (b *BootstrapDNSConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var single BootstrappedUpstreamConfig
	if err := unmarshal(&single); err == nil {
		*b = BootstrapDNSConfig{single}

		return nil
	}

	// bootstrapDNSConfig is used to avoid infinite recursion:
	// if we used BootstrapDNSConfig, unmarshal would just call us again.
	var c bootstrapDNSConfig
	if err := unmarshal(&c); err != nil {
		return err
	}

	*b = BootstrapDNSConfig(c)

	return nil
}

// UnmarshalYAML creates BootstrapConfig from YAML
func (b *BootstrappedUpstreamConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if err := unmarshal(&b.Upstream); err == nil {
		return nil
	}

	// bootstrapConfig is used to avoid infinite recursion:
	// if we used BootstrapConfig, unmarshal would just call us again.
	var c bootstrappedUpstreamConfig
	if err := unmarshal(&c); err != nil {
		return err
	}

	*b = BootstrappedUpstreamConfig(c)

	return nil
}

// Config main configuration
//
//nolint:maligned
type Config struct {
	Upstream            ParallelBestConfig        `yaml:"upstream"`
	UpstreamTimeout     Duration                  `yaml:"upstreamTimeout" default:"2s"`
	ConnectIPVersion    IPVersion                 `yaml:"connectIPVersion"`
	CustomDNS           CustomDNSConfig           `yaml:"customDNS"`
	Conditional         ConditionalUpstreamConfig `yaml:"conditional"`
	Blocking            BlockingConfig            `yaml:"blocking"`
	ClientLookup        ClientLookupConfig        `yaml:"clientLookup"`
	Caching             CachingConfig             `yaml:"caching"`
	QueryLog            QueryLogConfig            `yaml:"queryLog"`
	Prometheus          MetricsConfig             `yaml:"prometheus"`
	Redis               RedisConfig               `yaml:"redis"`
	Log                 log.Config                `yaml:"log"`
	Ports               PortsConfig               `yaml:"ports"`
	DoHUserAgent        string                    `yaml:"dohUserAgent"`
	MinTLSServeVer      string                    `yaml:"minTlsServeVersion" default:"1.2"`
	StartVerifyUpstream bool                      `yaml:"startVerifyUpstream" default:"false"`
	CertFile            string                    `yaml:"certFile"`
	KeyFile             string                    `yaml:"keyFile"`
	BootstrapDNS        BootstrapDNSConfig        `yaml:"bootstrapDns"`
	HostsFile           HostsFileConfig           `yaml:"hostsFile"`
	FqdnOnly            FqdnOnlyConfig            `yaml:",inline"`
	Filtering           FilteringConfig           `yaml:"filtering"`
	Ede                 EdeConfig                 `yaml:"ede"`
	// Deprecated
	DisableIPv6 bool `yaml:"disableIPv6" default:"false"`
	// Deprecated
	LogLevel log.Level `yaml:"logLevel" default:"info"`
	// Deprecated
	LogFormat log.FormatType `yaml:"logFormat" default:"text"`
	// Deprecated
	LogPrivacy bool `yaml:"logPrivacy" default:"false"`
	// Deprecated
	LogTimestamp bool `yaml:"logTimestamp" default:"true"`
	// Deprecated
	DNSPorts ListenConfig `yaml:"port" default:"53"`
	// Deprecated
	HTTPPorts ListenConfig `yaml:"httpPort"`
	// Deprecated
	HTTPSPorts ListenConfig `yaml:"httpsPort"`
	// Deprecated
	TLSPorts ListenConfig `yaml:"tlsPort"`
}

type PortsConfig struct {
	DNS   ListenConfig `yaml:"dns" default:"53"`
	HTTP  ListenConfig `yaml:"http"`
	HTTPS ListenConfig `yaml:"https"`
	TLS   ListenConfig `yaml:"tls"`
}

func (c *PortsConfig) LogConfig(logger *logrus.Entry) {
	logger.Infof("DNS   = %s", c.DNS)
	logger.Infof("TLS   = %s", c.TLS)
	logger.Infof("HTTP  = %s", c.HTTP)
	logger.Infof("HTTPS = %s", c.HTTPS)
}

// split in two types to avoid infinite recursion. See `BootstrapDNSConfig.UnmarshalYAML`.
type (
	BootstrapDNSConfig bootstrapDNSConfig
	bootstrapDNSConfig []BootstrappedUpstreamConfig
)

// split in two types to avoid infinite recursion. See `BootstrappedUpstreamConfig.UnmarshalYAML`.
type (
	BootstrappedUpstreamConfig bootstrappedUpstreamConfig
	bootstrappedUpstreamConfig struct {
		Upstream Upstream `yaml:"upstream"`
		IPs      []net.IP `yaml:"ips"`
	}
)

// RedisConfig configuration for the redis connection
type RedisConfig struct {
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

type (
	FqdnOnlyConfig = toEnable
	EdeConfig      = toEnable
)

type toEnable struct {
	Enable bool `yaml:"enable" default:"false"`
}

// IsEnabled implements `config.Configurable`.
func (c *toEnable) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *toEnable) LogConfig(logger *logrus.Entry) {
	logger.Info("enabled")
}

//nolint:gochecknoglobals
var (
	config  = &Config{}
	cfgLock sync.RWMutex
)

// LoadConfig creates new config from YAML file or a directory containing YAML files
func LoadConfig(path string, mandatory bool) (*Config, error) {
	cfgLock.Lock()
	defer cfgLock.Unlock()

	cfg := Config{}
	if err := defaults.Set(&cfg); err != nil {
		return nil, fmt.Errorf("can't apply default values: %w", err)
	}

	fs, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !mandatory {
			// config file does not exist
			// return config with default values
			config = &cfg

			return config, nil
		}

		return nil, fmt.Errorf("can't read config file(s): %w", err)
	}

	var data []byte

	if fs.IsDir() {
		data, err = readFromDir(path, data)

		if err != nil {
			return nil, fmt.Errorf("can't read config files: %w", err)
		}
	} else {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("can't read config file: %w", err)
		}
	}

	err = unmarshalConfig(data, &cfg)
	if err != nil {
		return nil, err
	}

	config = &cfg

	return &cfg, nil
}

func readFromDir(path string, data []byte) ([]byte, error) {
	err := filepath.WalkDir(path, func(filePath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if path == filePath {
			return nil
		}

		// Ignore non YAML files
		if !strings.HasSuffix(filePath, ".yml") && !strings.HasSuffix(filePath, ".yaml") {
			return nil
		}

		isRegular, err := isRegularFile(filePath)
		if err != nil {
			return err
		}

		// Ignore non regular files (directories, sockets, etc.)
		if !isRegular {
			return nil
		}

		fileData, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}

		data = append(data, []byte("\n")...)
		data = append(data, fileData...)

		return nil
	})

	return data, err
}

// isRegularFile follows symlinks, so the result is `true` for a symlink to a regular file.
func isRegularFile(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	isRegular := stat.Mode()&os.ModeType == 0

	return isRegular, nil
}

func unmarshalConfig(data []byte, cfg *Config) error {
	err := yaml.UnmarshalStrict(data, cfg)
	if err != nil {
		return fmt.Errorf("wrong file structure: %w", err)
	}

	validateConfig(cfg)

	return nil
}

func validateConfig(cfg *Config) {
	if cfg.DisableIPv6 {
		log.Log().Warnf("'disableIPv6' is deprecated. Please use 'filtering.queryTypes' with 'AAAA' instead.")

		cfg.Filtering.QueryTypes.Insert(dns.Type(dns.TypeAAAA))
	}

	if cfg.Blocking.FailStartOnListError {
		log.Log().Warnf("'blocking.failStartOnListError' is deprecated. Please use 'blocking.startStrategy'" +
			" with 'failOnError' instead.")

		if cfg.Blocking.StartStrategy == StartStrategyTypeBlocking {
			cfg.Blocking.StartStrategy = StartStrategyTypeFailOnError
		} else if cfg.Blocking.StartStrategy == StartStrategyTypeFast {
			log.Log().Warnf("'blocking.startStrategy' with 'fast' will ignore 'blocking.failStartOnListError'.")
		}
	}

	fixDeprecatedLog(cfg)

	fixDeprecatedPorts(cfg)
}

// fixDeprecatedLog ensures backwards compatibility for logging options
func fixDeprecatedLog(cfg *Config) {
	if cfg.LogLevel != log.LevelInfo && cfg.Log.Level == log.LevelInfo {
		log.Log().Warnf("'logLevel' is deprecated. Please use 'log.level' instead.")

		cfg.Log.Level = cfg.LogLevel
	}

	if cfg.LogFormat != log.FormatTypeText && cfg.Log.Format == log.FormatTypeText {
		log.Log().Warnf("'logFormat' is deprecated. Please use 'log.format' instead.")

		cfg.Log.Format = cfg.LogFormat
	}

	if cfg.LogPrivacy && !cfg.Log.Privacy {
		log.Log().Warnf("'logPrivacy' is deprecated. Please use 'log.privacy' instead.")

		cfg.Log.Privacy = cfg.LogPrivacy
	}

	if !cfg.LogTimestamp && cfg.Log.Timestamp {
		log.Log().Warnf("'logTimestamp' is deprecated. Please use 'log.timestamp' instead.")

		cfg.Log.Timestamp = cfg.LogTimestamp
	}
}

// fixDeprecatedPorts ensures backwards compatibility for ports options
func fixDeprecatedPorts(cfg *Config) {
	defaultDNSPort := ListenConfig([]string{"53"})
	if (len(cfg.DNSPorts) > 1 || (len(cfg.DNSPorts) == 1 && cfg.DNSPorts[0] != defaultDNSPort[0])) &&
		(len(cfg.Ports.DNS) == 1 && cfg.Ports.DNS[0] == defaultDNSPort[0]) {
		log.Log().Warnf("'port' is deprecated. Please use 'ports.dns' instead.")

		cfg.Ports.DNS = cfg.DNSPorts
	}

	if len(cfg.HTTPPorts) > 0 && len(cfg.Ports.HTTP) == 0 {
		log.Log().Warnf("'httpPort' is deprecated. Please use 'ports.http' instead.")

		cfg.Ports.HTTP = cfg.HTTPPorts
	}

	if len(cfg.HTTPSPorts) > 0 && len(cfg.Ports.HTTPS) == 0 {
		log.Log().Warnf("'httpsPort' is deprecated. Please use 'ports.https' instead.")

		cfg.Ports.HTTPS = cfg.HTTPSPorts
	}

	if len(cfg.TLSPorts) > 0 && len(cfg.Ports.TLS) == 0 {
		log.Log().Warnf("'tlsPort' is deprecated. Please use 'ports.tls' instead.")

		cfg.Ports.TLS = cfg.TLSPorts
	}
}

// GetConfig returns the current config
func GetConfig() *Config {
	cfgLock.RLock()
	defer cfgLock.RUnlock()

	return config
}

// ConvertPort converts string representation into a valid port (0 - 65535)
func ConvertPort(in string) (uint16, error) {
	const (
		base    = 10
		bitSize = 16
	)

	p, err := strconv.ParseUint(strings.TrimSpace(in), base, bitSize)
	if err != nil {
		return 0, err
	}

	return uint16(p), nil
}
