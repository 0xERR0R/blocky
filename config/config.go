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

	"blocky/log"

	"gopkg.in/yaml.v2"
)

const (
	validUpstream = `(?P<Host>(?:\[[^\]]+\])|[^\s/:]+):?(?P<Port>[^\s/:]*)?(?P<Path>/[^\s]*)?`
	// NetUDP UDP protocol (deprecated)
	NetUDP = "udp"

	// NetTCP TCP protocol (deprecated)
	NetTCP = "tcp"

	// NetTCPUDP TCP and UDP protocols
	NetTCPUDP = "tcp+udp"

	// NetTCPTLS TCP-TLS protocol
	NetTCPTLS = "tcp-tls"

	// NetHTTPS HTTPS protocol
	NetHTTPS = "https"
)

// nolint:gochecknoglobals
var netDefaultPort = map[string]uint16{
	NetTCPUDP: 53,
	NetTCPTLS: 853,
	NetHTTPS:  443,
}

// Upstream is the definition of external DNS server
type Upstream struct {
	Net  string
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

// ParseUpstream creates new Upstream from passed string in format [net]:host[:port][/path]
func ParseUpstream(upstream string) (result Upstream, err error) {
	if strings.TrimSpace(upstream) == "" {
		return Upstream{}, nil
	}

	var n string

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

func extractNet(upstream string) (string, string) {
	if strings.HasPrefix(upstream, NetTCP+":") {
		log.Log().Warnf("net prefix tcp is deprecated, using tcp+udp as default fallback")

		return NetTCPUDP, strings.Replace(upstream, NetTCP+":", "", 1)
	}

	if strings.HasPrefix(upstream, NetUDP+":") {
		log.Log().Warnf("net prefix udp is deprecated, using tcp+udp as default fallback")
		return NetTCPUDP, strings.Replace(upstream, NetUDP+":", "", 1)
	}

	if strings.HasPrefix(upstream, NetTCPUDP+":") {
		return NetTCPUDP, strings.Replace(upstream, NetTCPUDP+":", "", 1)
	}

	if strings.HasPrefix(upstream, NetTCPTLS+":") {
		return NetTCPTLS, strings.Replace(upstream, NetTCPTLS+":", "", 1)
	}

	if strings.HasPrefix(upstream, NetHTTPS+":") {
		return NetHTTPS, strings.Replace(upstream, NetHTTPS+":", "", 1)
	}

	return NetTCPUDP, upstream
}

const (
	cfgDefaultPort           = "53"
	cfgDefaultPrometheusPath = "/metrics"
)

// Config main configuration
// nolint:maligned
type Config struct {
	Upstream     UpstreamConfig            `yaml:"upstream"`
	CustomDNS    CustomDNSConfig           `yaml:"customDNS"`
	Conditional  ConditionalUpstreamConfig `yaml:"conditional"`
	Blocking     BlockingConfig            `yaml:"blocking"`
	ClientLookup ClientLookupConfig        `yaml:"clientLookup"`
	Caching      CachingConfig             `yaml:"caching"`
	QueryLog     QueryLogConfig            `yaml:"queryLog"`
	Prometheus   PrometheusConfig          `yaml:"prometheus"`
	LogLevel     string                    `yaml:"logLevel"`
	LogFormat    string                    `yaml:"logFormat"`
	LogTimestamp bool                      `yaml:"logTimestamp"`
	Port         string                    `yaml:"port"`
	HTTPPort     uint16                    `yaml:"httpPort"`
	HTTPSPort    uint16                    `yaml:"httpsPort"`
	DisableIPv6  bool                      `yaml:"disableIPv6"`
	CertFile     string                    `yaml:"httpsCertFile"`
	KeyFile      string                    `yaml:"httpsKeyFile"`
	BootstrapDNS Upstream                  `yaml:"bootstrapDns"`
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
	RefreshPeriod     int                 `yaml:"refreshPeriod"`
}

// ClientLookupConfig configuration for the client lookup
type ClientLookupConfig struct {
	ClientnameIPMapping map[string][]net.IP `yaml:"clients"`
	Upstream            Upstream            `yaml:"upstream"`
	SingleNameOrder     []uint              `yaml:"singleNameOrder"`
}

// CachingConfig configuration for domain caching
type CachingConfig struct {
	MinCachingTime int  `yaml:"minTime"`
	MaxCachingTime int  `yaml:"maxTime"`
	Prefetching    bool `yaml:"prefetching"`
}

// QueryLogConfig configuration for the query logging
type QueryLogConfig struct {
	Dir              string `yaml:"dir"`
	PerClient        bool   `yaml:"perClient"`
	LogRetentionDays uint64 `yaml:"logRetentionDays"`
}

// NewConfig creates new config from YAML file
func NewConfig(path string, mandatory bool) Config {
	cfg := Config{}
	setDefaultValues(&cfg)

	data, err := ioutil.ReadFile(path)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !mandatory {
			// config file does not exist
			// return config with default values
			return cfg
		}

		log.Log().Fatal("Can't read config file: ", err)
	}

	err = yaml.UnmarshalStrict(data, &cfg)
	if err != nil {
		log.Log().Fatal("wrong file structure: ", err)
	}

	if cfg.LogFormat != log.CfgLogFormatText && cfg.LogFormat != log.CfgLogFormatJSON {
		log.Log().Fatal("LogFormat should be 'text' or 'json'")
	}

	return cfg
}

func setDefaultValues(cfg *Config) {
	cfg.Port = cfgDefaultPort
	cfg.LogLevel = "info"
	cfg.LogFormat = log.CfgLogFormatText
	cfg.LogTimestamp = true
	cfg.Prometheus.Path = cfgDefaultPrometheusPath
}
