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

	"github.com/0xERR0R/blocky/log"
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
// none // use logger as fallback
// mysql // MySQL or MariaDB database
// csv // CSV file per day
// csv-client // CSV file per day and client
// )
type QueryLogType int16

type Duration time.Duration

const (
	validUpstream = `(?P<Host>(?:\[[^\]]+\])|[^\s/:]+):?(?P<Port>[^\s/:]*)?(?P<Path>/[^\s]*)?`
)

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
		return err
	}

	*u = upstream

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
				return err
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

// ParseUpstream creates new Upstream from passed string in format [net]:host[:port][/path]
func ParseUpstream(upstream string) (result Upstream, err error) {
	if strings.TrimSpace(upstream) == "" {
		return Upstream{}, nil
	}

	var n NetProtocol

	n, upstream = extractNet(upstream)

	r := regexp.MustCompile(validUpstream)

	match := r.FindStringSubmatch(upstream)

	host := match[1]

	portPart := match[2]

	path := match[3]

	var port uint16

	if len(portPart) > 0 {
		var p uint64
		p, err = strconv.ParseUint(strings.TrimSpace(portPart), 10, 16)

		if err != nil {
			err = fmt.Errorf("can't convert port to number (1 - 65535) %w", err)
			return
		}

		port = uint16(p)
	} else {
		port = netDefaultPort[n]
	}

	host = regexp.MustCompile(`[\[\]]`).ReplaceAllString(host, "")

	return Upstream{Net: n, Host: host, Port: port, Path: path}, nil
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
		return NetProtocolHttps, strings.Replace(upstream, NetProtocolHttps.String()+":", "", 1)
	}

	return NetProtocolTcpUdp, upstream
}

const (
	cfgDefaultPort            = "53"
	cfgDefaultPrometheusPath  = "/metrics"
	cfgDefaultUpstreamTimeout = Duration(2 * time.Second)
	cfgDefaultRefreshPeriod   = Duration(4 * time.Hour)
	cfgDefaultDownloadTimeout = Duration(60 * time.Second)
)

// Config main configuration
// nolint:maligned
type Config struct {
	Upstream        UpstreamConfig            `yaml:"upstream"`
	UpstreamTimeout Duration                  `yaml:"upstreamTimeout"`
	CustomDNS       CustomDNSConfig           `yaml:"customDNS"`
	Conditional     ConditionalUpstreamConfig `yaml:"conditional"`
	Blocking        BlockingConfig            `yaml:"blocking"`
	ClientLookup    ClientLookupConfig        `yaml:"clientLookup"`
	Caching         CachingConfig             `yaml:"caching"`
	QueryLog        QueryLogConfig            `yaml:"queryLog"`
	Prometheus      PrometheusConfig          `yaml:"prometheus"`
	LogLevel        log.Level                 `yaml:"logLevel"`
	LogFormat       log.FormatType            `yaml:"logFormat"`
	LogPrivacy      bool                      `yaml:"logPrivacy"`
	LogTimestamp    bool                      `yaml:"logTimestamp"`
	Port            string                    `yaml:"port"`
	HTTPPort        string                    `yaml:"httpPort"`
	HTTPSPort       string                    `yaml:"httpsPort"`
	DisableIPv6     bool                      `yaml:"disableIPv6"`
	CertFile        string                    `yaml:"httpsCertFile"`
	KeyFile         string                    `yaml:"httpsKeyFile"`
	BootstrapDNS    Upstream                  `yaml:"bootstrapDns"`
}

// PrometheusConfig contains the config values for prometheus
type PrometheusConfig struct {
	Enable bool   `yaml:"enable"`
	Path   string `yaml:"path"`
}

// UpstreamConfig upstream server configuration
type UpstreamConfig struct {
	ExternalResolvers map[string][]Upstream `yaml:",inline"`
}

// CustomDNSConfig custom DNS configuration
type CustomDNSConfig struct {
	Mapping CustomDNSMapping `yaml:"mapping"`
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
	BlackLists        map[string][]string `yaml:"blackLists"`
	WhiteLists        map[string][]string `yaml:"whiteLists"`
	ClientGroupsBlock map[string][]string `yaml:"clientGroupsBlock"`
	BlockType         string              `yaml:"blockType"`
	BlockTTL          Duration            `yaml:"blockTTL"`
	DownloadTimeout   Duration            `yaml:"downloadTimeout"`
	RefreshPeriod     Duration            `yaml:"refreshPeriod"`
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
	MaxItemsCount         int      `yaml:"maxItemsCount"`
	Prefetching           bool     `yaml:"prefetching"`
	PrefetchExpires       Duration `yaml:"prefetchExpires"`
	PrefetchThreshold     int      `yaml:"prefetchThreshold"`
	PrefetchMaxItemsCount int      `yaml:"prefetchMaxItemsCount"`
}

// QueryLogConfig configuration for the query logging
type QueryLogConfig struct {
	// Deprecated
	Dir string `yaml:"dir"`
	// Deprecated
	PerClient        bool         `yaml:"perClient"`
	Target           string       `yaml:"target"`
	Type             QueryLogType `yaml:"type"`
	LogRetentionDays uint64       `yaml:"logRetentionDays"`
}

// nolint:gochecknoglobals
var config = &Config{}

// LoadConfig creates new config from YAML file
func LoadConfig(path string, mandatory bool) {
	cfg := Config{}
	setDefaultValues(&cfg)

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

		if cfg.QueryLog.Type == QueryLogTypeNone {
			if cfg.QueryLog.PerClient {
				cfg.QueryLog.Type = QueryLogTypeCsvClient
			} else {
				cfg.QueryLog.Type = QueryLogTypeCsv
			}
		}
	}
}

// GetConfig returns the current config
func GetConfig() *Config {
	return config
}

func setDefaultValues(cfg *Config) {
	cfg.Port = cfgDefaultPort
	cfg.LogTimestamp = true
	cfg.Prometheus.Path = cfgDefaultPrometheusPath
	cfg.UpstreamTimeout = cfgDefaultUpstreamTimeout
	cfg.Blocking.RefreshPeriod = cfgDefaultRefreshPeriod
	cfg.Blocking.DownloadTimeout = cfgDefaultDownloadTimeout
}
