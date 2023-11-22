//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names --values
package config

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"

	. "github.com/0xERR0R/blocky/config/migration"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"
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
	// The behavior of this method is undefined when `IsEnabled` returns false.
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

// TLSVersion represents a TLS protocol version. ENUM(
// 1.0 = 769
// 1.1
// 1.2
// 1.3
// )
type TLSVersion int // values MUST match `tls.VersionTLS*`

func (v *TLSVersion) validate(logger *logrus.Entry) {
	// So we get a linting error if it is considered insecure in the future
	minAllowed := tls.Config{MinVersion: tls.VersionTLS12}.MinVersion

	if *v < TLSVersion(minAllowed) {
		def := mustDefault[Config]().MinTLSServeVer

		logger.Warnf("TLS version %s is insecure, using %s instead", v, def)
		*v = def
	}
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

func (s *StartStrategyType) do(setup func() error, logErr func(error)) error {
	if *s == StartStrategyTypeFast {
		go func() {
			err := setup()
			if err != nil {
				logErr(err)
			}
		}()

		return nil
	}

	err := setup()
	if err != nil {
		logErr(err)

		if *s == StartStrategyTypeFailOnError {
			return err
		}
	}

	return nil
}

// QueryLogField data field to be logged
// ENUM(clientIP,clientName,responseReason,responseAnswer,question,duration)
type QueryLogField string

// UpstreamStrategy data field to be logged
// ENUM(parallel_best,strict,random)
type UpstreamStrategy uint8

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
	Upstreams        Upstreams           `yaml:"upstreams"`
	ConnectIPVersion IPVersion           `yaml:"connectIPVersion"`
	CustomDNS        CustomDNS           `yaml:"customDNS"`
	Conditional      ConditionalUpstream `yaml:"conditional"`
	Blocking         Blocking            `yaml:"blocking"`
	ClientLookup     ClientLookup        `yaml:"clientLookup"`
	Caching          CachingConfig       `yaml:"caching"`
	QueryLog         QueryLogConfig      `yaml:"queryLog"`
	Prometheus       MetricsConfig       `yaml:"prometheus"`
	Redis            RedisConfig         `yaml:"redis"`
	Log              log.Config          `yaml:"log"`
	Ports            PortsConfig         `yaml:"ports"`
	MinTLSServeVer   TLSVersion          `yaml:"minTlsServeVersion" default:"1.2"`
	CertFile         string              `yaml:"certFile"`
	KeyFile          string              `yaml:"keyFile"`
	BootstrapDNS     BootstrapDNSConfig  `yaml:"bootstrapDns"`
	HostsFile        HostsFileConfig     `yaml:"hostsFile"`
	FQDNOnly         FQDNOnly            `yaml:"fqdnOnly"`
	Filtering        FilteringConfig     `yaml:"filtering"`
	EDE              EDE                 `yaml:"ede"`
	ECS              ECS                 `yaml:"ecs"`
	SUDN             SUDN                `yaml:"specialUseDomains"`

	// Deprecated options
	Deprecated struct {
		Upstream            *UpstreamGroups `yaml:"upstream"`
		UpstreamTimeout     *Duration       `yaml:"upstreamTimeout"`
		DisableIPv6         *bool           `yaml:"disableIPv6"`
		LogLevel            *log.Level      `yaml:"logLevel"`
		LogFormat           *log.FormatType `yaml:"logFormat"`
		LogPrivacy          *bool           `yaml:"logPrivacy"`
		LogTimestamp        *bool           `yaml:"logTimestamp"`
		DNSPorts            *ListenConfig   `yaml:"port"`
		HTTPPorts           *ListenConfig   `yaml:"httpPort"`
		HTTPSPorts          *ListenConfig   `yaml:"httpsPort"`
		TLSPorts            *ListenConfig   `yaml:"tlsPort"`
		StartVerifyUpstream *bool           `yaml:"startVerifyUpstream"`
		DoHUserAgent        *string         `yaml:"dohUserAgent"`
	} `yaml:",inline"`
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
	FQDNOnly = toEnable
	EDE      = toEnable
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

type SourceLoadingConfig struct {
	Concurrency        uint              `yaml:"concurrency" default:"4"`
	MaxErrorsPerSource int               `yaml:"maxErrorsPerSource" default:"5"`
	RefreshPeriod      Duration          `yaml:"refreshPeriod" default:"4h"`
	Strategy           StartStrategyType `yaml:"strategy" default:"blocking"`
	Downloads          DownloaderConfig  `yaml:"downloads"`
}

func (c *SourceLoadingConfig) LogConfig(logger *logrus.Entry) {
	logger.Infof("concurrency = %d", c.Concurrency)
	logger.Debugf("maxErrorsPerSource = %d", c.MaxErrorsPerSource)
	logger.Debugf("strategy = %s", c.Strategy)

	if c.RefreshPeriod.IsAboveZero() {
		logger.Infof("refresh = every %s", c.RefreshPeriod)
	} else {
		logger.Debug("refresh = disabled")
	}

	logger.Info("downloads:")
	log.WithIndent(logger, "  ", c.Downloads.LogConfig)
}

func (c *SourceLoadingConfig) StartPeriodicRefresh(ctx context.Context,
	refresh func(context.Context) error,
	logErr func(error),
) error {
	refreshAndRecover := func(ctx context.Context) (rerr error) {
		defer func() {
			if val := recover(); val != nil {
				rerr = fmt.Errorf("refresh function panicked: %v", val)
			}
		}()

		return refresh(ctx)
	}

	err := c.Strategy.do(func() error { return refreshAndRecover(context.Background()) }, logErr)
	if err != nil {
		return err
	}

	if c.RefreshPeriod > 0 {
		go c.periodically(ctx, refreshAndRecover, logErr)
	}

	return nil
}

func (c *SourceLoadingConfig) periodically(ctx context.Context,
	refresh func(context.Context) error,
	logErr func(error),
) {
	ticker := time.NewTicker(c.RefreshPeriod.ToDuration())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := refresh(ctx)
			if err != nil {
				logErr(err)
			}

		case <-ctx.Done():
			return
		}
	}
}

type DownloaderConfig struct {
	Timeout  Duration `yaml:"timeout" default:"5s"`
	Attempts uint     `yaml:"attempts" default:"3"`
	Cooldown Duration `yaml:"cooldown" default:"500ms"`
}

func (c *DownloaderConfig) LogConfig(logger *logrus.Entry) {
	logger.Infof("timeout = %s", c.Timeout)
	logger.Infof("attempts = %d", c.Attempts)
	logger.Debugf("cooldown = %s", c.Cooldown)
}

func WithDefaults[T any]() (T, error) {
	var cfg T

	if err := defaults.Set(&cfg); err != nil {
		return cfg, fmt.Errorf("can't apply %T defaults: %w", cfg, err)
	}

	return cfg, nil
}

func mustDefault[T any]() T {
	cfg, err := WithDefaults[T]()
	if err != nil {
		util.FatalOnError("broken defaults", err)
	}

	return cfg
}

// LoadConfig creates new config from YAML file or a directory containing YAML files
func LoadConfig(path string, mandatory bool) (rCfg *Config, rerr error) {
	cfg, err := WithDefaults[Config]()
	if err != nil {
		return nil, err
	}

	defer func() {
		if rerr == nil {
			util.LogPrivacy.Store(rCfg.Log.Privacy)
		}
	}()

	fs, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !mandatory {
			// config file does not exist
			// return config with default values
			return &cfg, nil
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

	logger := logrus.NewEntry(log.Log())

	usesDepredOpts := cfg.migrate(logger)
	if usesDepredOpts {
		logger.Error("configuration uses deprecated options, see warning logs for details")
	}

	cfg.validate(logger)

	return nil
}

func (cfg *Config) migrate(logger *logrus.Entry) bool {
	usesDepredOpts := Migrate(logger, "", cfg.Deprecated, map[string]Migrator{
		"upstream":        Move(To("upstreams.groups", &cfg.Upstreams)),
		"upstreamTimeout": Move(To("upstreams.timeout", &cfg.Upstreams)),
		"disableIPv6": Apply(To("filtering.queryTypes", &cfg.Filtering), func(oldValue bool) {
			if oldValue {
				cfg.Filtering.QueryTypes.Insert(dns.Type(dns.TypeAAAA))
			}
		}),
		"port":                Move(To("ports.dns", &cfg.Ports)),
		"httpPort":            Move(To("ports.http", &cfg.Ports)),
		"httpsPort":           Move(To("ports.https", &cfg.Ports)),
		"tlsPort":             Move(To("ports.tls", &cfg.Ports)),
		"logLevel":            Move(To("log.level", &cfg.Log)),
		"logFormat":           Move(To("log.format", &cfg.Log)),
		"logPrivacy":          Move(To("log.privacy", &cfg.Log)),
		"logTimestamp":        Move(To("log.timestamp", &cfg.Log)),
		"startVerifyUpstream": Move(To("upstreams.startVerify", &cfg.Upstreams)),
		"dohUserAgent":        Move(To("upstreams.userAgent", &cfg.Upstreams)),
	})

	usesDepredOpts = cfg.Blocking.migrate(logger) || usesDepredOpts
	usesDepredOpts = cfg.HostsFile.migrate(logger) || usesDepredOpts

	return usesDepredOpts
}

func (cfg *Config) validate(logger *logrus.Entry) {
	cfg.MinTLSServeVer.validate(logger)
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
