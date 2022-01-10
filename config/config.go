//go:generate go-enum -f=$GOFILE --marshal --names
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hako/durafmt"

	"github.com/0xERR0R/blocky/log"
	"github.com/creasty/defaults"
	"gopkg.in/yaml.v2"
)

// NetProtocol resolver protocol ENUM(
// udp // Deprecated: use tcp+udp instead
// tcp // Deprecated: use tcp+udp instead
// tcp+udp // TCP and UDP protocols
// tcp-tls // TCP-TLS protocol
// https // HTTPS protocol
// )
type NetProtocol uint16

// QueryLogType type of the query log ENUM(
// console // use logger as fallback
// none // no logging
// mysql // MySQL or MariaDB database
// postgresql // PostgreSQL database
// csv // CSV file per day
// csv-client // CSV file per day and client
// )
type QueryLogType int16

type Duration time.Duration

func (c *Duration) String() string {
	return durafmt.Parse(time.Duration(*c)).String()
}

// nolint:gochecknoglobals
var netDefaultPort = map[NetProtocol]uint16{
	NetProtocolTcpUdp: 53,
	NetProtocolTcpTls: 853,
	NetProtocolHttps:  443,
}

// Upstream is the definition of external DNS server
type Upstream struct {
	Net  NetProtocol
	Host string
	Port uint16
	Path string
}

// UnmarshalYAML creates Upstream from YAML
func (u *Upstream) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	upstream, err := ParseUpstream(s)
	if err != nil {
		return fmt.Errorf("can't convert upstream '%s': %w", s, err)
	}

	*u = upstream

	return nil
}

// ListenConfig is a list of address(es) to listen on
type ListenConfig []string

// UnmarshalYAML creates ListenConfig from YAML
func (l *ListenConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var addresses string
	if err := unmarshal(&addresses); err != nil {
		var port uint16
		if err := unmarshal(&port); err != nil {
			return err
		}

		addresses = fmt.Sprintf("%d", port)
	}

	*l = strings.Split(addresses, ",")

	return nil
}

// UnmarshalYAML creates ConditionalUpstreamMapping from YAML
func (c *ConditionalUpstreamMapping) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input map[string]string
	if err := unmarshal(&input); err != nil {
		return err
	}

	result := make(map[string][]Upstream)

	for k, v := range input {
		var upstreams []Upstream

		for _, part := range strings.Split(v, ",") {
			upstream, err := ParseUpstream(strings.TrimSpace(part))
			if err != nil {
				return fmt.Errorf("can't convert upstream '%s': %w", strings.TrimSpace(part), err)
			}

			upstreams = append(upstreams, upstream)
		}

		result[k] = upstreams
	}

	c.Upstreams = result

	return nil
}

// UnmarshalYAML creates CustomDNSMapping from YAML
func (c *CustomDNSMapping) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input map[string]string
	if err := unmarshal(&input); err != nil {
		return err
	}

	result := make(map[string][]net.IP)

	for k, v := range input {
		var ips []net.IP

		for _, part := range strings.Split(v, ",") {
			ip := net.ParseIP(strings.TrimSpace(part))
			if ip == nil {
				return fmt.Errorf("invalid IP address '%s'", part)
			}

			ips = append(ips, ip)
		}

		result[k] = ips
	}

	c.HostIPs = result

	return nil
}

// UnmarshalYAML creates Duration from YAML. If no unit is used, uses minutes
func (c *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input string
	if err := unmarshal(&input); err != nil {
		return err
	}

	if minutes, err := strconv.Atoi(input); err == nil {
		// duration is defined as number without unit
		// use minutes to ensure back compatibility
		*c = Duration(time.Duration(minutes) * time.Minute)
		return nil
	}

	duration, err := time.ParseDuration(input)
	if err == nil {
		*c = Duration(duration)
		return nil
	}

	return err
}

var validDomain = regexp.MustCompile(
	`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

// ParseUpstream creates new Upstream from passed string in format [net]:host[:port][/path]
func ParseUpstream(upstream string) (Upstream, error) {
	var path string

	var port uint16

	n, upstream := extractNet(upstream)

	path, upstream = extractPath(upstream)

	host, portString, err := net.SplitHostPort(upstream)

	// string contains host:port
	if err == nil {
		var p uint64
		p, err = strconv.ParseUint(strings.TrimSpace(portString), 10, 16)

		if err != nil {
			err = fmt.Errorf("can't convert port to number (1 - 65535) %w", err)
			return Upstream{}, err
		}

		port = uint16(p)
	} else {
		// only host, use default port
		host = upstream
		port = netDefaultPort[n]
	}

	// validate hostname or ip
	ip := net.ParseIP(host)

	if ip == nil {
		// is not IP
		if !validDomain.MatchString(host) {
			return Upstream{}, fmt.Errorf("wrong host name '%s'", host)
		}
	}

	return Upstream{
		Net:  n,
		Host: host,
		Port: port,
		Path: path,
	}, nil
}

func extractPath(in string) (path string, upstream string) {
	slashIdx := strings.Index(in, "/")

	if slashIdx >= 0 {
		path = in[slashIdx:]
		upstream = in[:slashIdx]
	} else {
		upstream = in
	}

	return
}

func extractNet(upstream string) (NetProtocol, string) {
	if strings.HasPrefix(upstream, NetProtocolTcp.String()+":") {
		log.Log().Warnf("net prefix tcp is deprecated, using tcp+udp as default fallback")

		return NetProtocolTcpUdp, strings.Replace(upstream, NetProtocolTcp.String()+":", "", 1)
	}

	if strings.HasPrefix(upstream, NetProtocolUdp.String()+":") {
		log.Log().Warnf("net prefix udp is deprecated, using tcp+udp as default fallback")
		return NetProtocolTcpUdp, strings.Replace(upstream, NetProtocolUdp.String()+":", "", 1)
	}

	if strings.HasPrefix(upstream, NetProtocolTcpUdp.String()+":") {
		return NetProtocolTcpUdp, strings.Replace(upstream, NetProtocolTcpUdp.String()+":", "", 1)
	}

	if strings.HasPrefix(upstream, NetProtocolTcpTls.String()+":") {
		return NetProtocolTcpTls, strings.Replace(upstream, NetProtocolTcpTls.String()+":", "", 1)
	}

	if strings.HasPrefix(upstream, NetProtocolHttps.String()+":") {
		return NetProtocolHttps, strings.TrimPrefix(strings.Replace(upstream, NetProtocolHttps.String()+":", "", 1), "//")
	}

	return NetProtocolTcpUdp, upstream
}

// Config main configuration
// nolint:maligned
type Config struct {
	Upstream        UpstreamConfig            `yaml:"upstream"`
	UpstreamTimeout Duration                  `yaml:"upstreamTimeout" default:"2s"`
	CustomDNS       CustomDNSConfig           `yaml:"customDNS"`
	Conditional     ConditionalUpstreamConfig `yaml:"conditional"`
	Blocking        BlockingConfig            `yaml:"blocking"`
	ClientLookup    ClientLookupConfig        `yaml:"clientLookup"`
	Caching         CachingConfig             `yaml:"caching"`
	QueryLog        QueryLogConfig            `yaml:"queryLog"`
	Prometheus      PrometheusConfig          `yaml:"prometheus"`
	Redis           RedisConfig               `yaml:"redis"`
	LogLevel        log.Level                 `yaml:"logLevel" default:"info"`
	LogFormat       log.FormatType            `yaml:"logFormat" default:"text"`
	LogPrivacy      bool                      `yaml:"logPrivacy" default:"false"`
	LogTimestamp    bool                      `yaml:"logTimestamp" default:"true"`
	DNSPorts        ListenConfig              `yaml:"port" default:"[\"53\"]"`
	HTTPPorts       ListenConfig              `yaml:"httpPort"`
	HTTPSPorts      ListenConfig              `yaml:"httpsPort"`
	TLSPorts        ListenConfig              `yaml:"tlsPort"`
	DisableIPv6     bool                      `yaml:"disableIPv6" default:"false"`
	CertFile        string                    `yaml:"certFile"`
	KeyFile         string                    `yaml:"keyFile"`
	BootstrapDNS    Upstream                  `yaml:"bootstrapDns"`
	HostsFile       HostsFileConfig           `yaml:"hostsFile"`
	// Deprecated
	HTTPCertFile string `yaml:"httpsCertFile"`
	// Deprecated
	HTTPKeyFile string `yaml:"httpsKeyFile"`
}

// PrometheusConfig contains the config values for prometheus
type PrometheusConfig struct {
	Enable bool   `yaml:"enable" default:"false"`
	Path   string `yaml:"path" default:"/metrics"`
}

// UpstreamConfig upstream server configuration
type UpstreamConfig struct {
	ExternalResolvers map[string][]Upstream `yaml:",inline"`
}

// CustomDNSConfig custom DNS configuration
type CustomDNSConfig struct {
	CustomTTL Duration         `yaml:"customTTL" default:"1h"`
	Mapping   CustomDNSMapping `yaml:"mapping"`
}

// CustomDNSMapping mapping for the custom DNS configuration
type CustomDNSMapping struct {
	HostIPs map[string][]net.IP
}

// ConditionalUpstreamConfig conditional upstream configuration
type ConditionalUpstreamConfig struct {
	Rewrite map[string]string          `yaml:"rewrite"`
	Mapping ConditionalUpstreamMapping `yaml:"mapping"`
}

// ConditionalUpstreamMapping mapping for conditional configuration
type ConditionalUpstreamMapping struct {
	Upstreams map[string][]Upstream
}

// BlockingConfig configuration for query blocking
type BlockingConfig struct {
	BlackLists           map[string][]string `yaml:"blackLists"`
	WhiteLists           map[string][]string `yaml:"whiteLists"`
	ClientGroupsBlock    map[string][]string `yaml:"clientGroupsBlock"`
	BlockType            string              `yaml:"blockType" default:"ZEROIP"`
	BlockTTL             Duration            `yaml:"blockTTL" default:"6h"`
	DownloadTimeout      Duration            `yaml:"downloadTimeout" default:"60s"`
	DownloadAttempts     int                 `yaml:"downloadAttempts" default:"3"`
	DownloadCooldown     Duration            `yaml:"downloadCooldown" default:"1s"`
	RefreshPeriod        Duration            `yaml:"refreshPeriod" default:"4h"`
	FailStartOnListError bool                `yaml:"failStartOnListError" default:"false"`
}

// ClientLookupConfig configuration for the client lookup
type ClientLookupConfig struct {
	ClientnameIPMapping map[string][]net.IP `yaml:"clients"`
	Upstream            Upstream            `yaml:"upstream"`
	SingleNameOrder     []uint              `yaml:"singleNameOrder"`
}

// CachingConfig configuration for domain caching
type CachingConfig struct {
	MinCachingTime        Duration `yaml:"minTime"`
	MaxCachingTime        Duration `yaml:"maxTime"`
	CacheTimeNegative     Duration `yaml:"cacheTimeNegative" default:"30m"`
	MaxItemsCount         int      `yaml:"maxItemsCount"`
	Prefetching           bool     `yaml:"prefetching"`
	PrefetchExpires       Duration `yaml:"prefetchExpires" default:"2h"`
	PrefetchThreshold     int      `yaml:"prefetchThreshold" default:"5"`
	PrefetchMaxItemsCount int      `yaml:"prefetchMaxItemsCount"`
}

// QueryLogConfig configuration for the query logging
type QueryLogConfig struct {
	// Deprecated
	Dir string `yaml:"dir"`
	// Deprecated
	PerClient        bool         `yaml:"perClient" default:"false"`
	Target           string       `yaml:"target"`
	Type             QueryLogType `yaml:"type"`
	LogRetentionDays uint64       `yaml:"logRetentionDays"`
	CreationAttempts int          `yaml:"creationAttempts" default:"3"`
	CreationCooldown Duration     `yaml:"creationCooldown" default:"2s"`
}

// RedisConfig configuration for the redis connection
type RedisConfig struct {
	Address            string   `yaml:"address"`
	Password           string   `yaml:"password" default:""`
	Database           int      `yaml:"database" default:"0"`
	Required           bool     `yaml:"required" default:"false"`
	ConnectionAttempts int      `yaml:"connectionAttempts" default:"3"`
	ConnectionCooldown Duration `yaml:"connectionCooldown" default:"1s"`
}

type HostsFileConfig struct {
	Filepath      string   `yaml:"filePath"`
	HostsTTL      Duration `yaml:"hostsTTL" default:"1h"`
	RefreshPeriod Duration `yaml:"refreshPeriod" default:"1h"`
}

// nolint:gochecknoglobals
var config = &Config{}

// LoadConfig creates new config from YAML file
func LoadConfig(path string, mandatory bool) {
	cfg := Config{}
	if err := defaults.Set(&cfg); err != nil {
		log.Log().Fatal("Can't apply default values: ", err)
	}

	data, err := ioutil.ReadFile(path)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !mandatory {
			// config file does not exist
			// return config with default values
			config = &cfg
			return
		}

		log.Log().Fatal("Can't read config file: ", err)
	}

	unmarshalConfig(data, cfg)
}

func unmarshalConfig(data []byte, cfg Config) {
	err := yaml.UnmarshalStrict(data, &cfg)
	if err != nil {
		log.Log().Fatal("wrong file structure: ", err)
	}

	validateConfig(&cfg)

	config = &cfg
}

func validateConfig(cfg *Config) {
	if cfg.QueryLog.Dir != "" {
		log.Log().Warnf("queryLog.Dir is deprecated, use 'queryLog.target' instead")

		if cfg.QueryLog.Target == "" {
			cfg.QueryLog.Target = cfg.QueryLog.Dir
		}

		if cfg.QueryLog.Type == QueryLogTypeConsole {
			if cfg.QueryLog.PerClient {
				cfg.QueryLog.Type = QueryLogTypeCsvClient
			} else {
				cfg.QueryLog.Type = QueryLogTypeCsv
			}
		}
	}

	if cfg.HTTPKeyFile != "" || cfg.HTTPCertFile != "" {
		log.Log().Warnf("'httpsCertFile'/'httpsKeyFile' are deprecated, use 'certFile'/'keyFile' instead")

		if cfg.CertFile == "" && cfg.KeyFile == "" {
			cfg.CertFile = cfg.HTTPCertFile
			cfg.KeyFile = cfg.HTTPKeyFile
		}
	}

	if len(cfg.TLSPorts) != 0 && (cfg.CertFile == "" || cfg.KeyFile == "") {
		log.Log().Fatal("certFile and keyFile parameters are mandatory for TLS")
	}

	if len(cfg.HTTPSPorts) != 0 && (cfg.CertFile == "" || cfg.KeyFile == "") {
		log.Log().Fatal("certFile and keyFile parameters are mandatory for HTTPS")
	}
}

// GetConfig returns the current config
func GetConfig() *Config {
	return config
}
