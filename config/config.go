package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

const (
	validUpstream = `(?P<Host>(?:\[[^\]]+\])|[^\s/:]+):?(?P<Port>[^\s/:]*)?(?P<Path>/[^\s]*)?`
	// deprecated
	NetUDP = "udp"
	// deprecated
	NetTCP    = "tcp"
	NetTCPUDP = "tcp+udp"
	NetTCPTLS = "tcp-tls"
	NetHTTPS  = "https"
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

// ParseUpstream creates new Upstream from passed string in format [net]:host[:port][/path]
func ParseUpstream(upstream string) (result Upstream, err error) {
	if strings.TrimSpace(upstream) == "" {
		return Upstream{}, nil
	}

	var n string

	n, upstream = extractNet(upstream)

	r := regexp.MustCompile(validUpstream)

	match := r.FindStringSubmatch(upstream)

	if len(match) == 0 {
		err = fmt.Errorf("wrong configuration, couldn't parse input '%s', please enter [net:]host[:port][/path]", upstream)
		return
	}

	if _, ok := netDefaultPort[n]; !ok {
		err = fmt.Errorf("wrong configuration, couldn't parse net '%s', please use one of %s",
			n, reflect.ValueOf(netDefaultPort).MapKeys())
		return
	}

	host := match[1]
	if len(host) == 0 {
		err = errors.New("wrong configuration, host wasn't specified")
		return
	}

	portPart := match[2]

	path := match[3]

	var port uint16

	if len(portPart) > 0 {
		var p int
		p, err = strconv.Atoi(strings.TrimSpace(portPart))

		if err != nil {
			err = fmt.Errorf("can't convert port to number %v", err)
			return
		}

		if p < 1 || p > 65535 {
			err = fmt.Errorf("invalid port %d", p)
			return
		}

		port = uint16(p)
	} else {
		port = netDefaultPort[n]
	}

	return Upstream{Net: n, Host: host, Port: port, Path: path}, nil
}

func extractNet(upstream string) (string, string) {
	if strings.HasPrefix(upstream, NetTCP+":") {
		log.Warnf("net prefix tcp is deprecated, using tcp+udp as default fallback")

		return NetTCPUDP, strings.Replace(upstream, NetTCP+":", "", 1)
	}

	if strings.HasPrefix(upstream, NetUDP+":") {
		log.Warnf("net prefix udp is deprecated, using tcp+udp as default fallback")
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
	cfgDefaultPort           = 53
	cfgDefaultPrometheusPath = "/metrics"
)

const (
	CfgLogFormatText = "text"
	CfgLogFormatJSON = "json"
)

// main configuration
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
	Port         uint16                    `yaml:"port"`
	HTTPPort     uint16                    `yaml:"httpPort"`
	HTTPSPort    uint16                    `yaml:"httpsPort"`
	CertFile     string                    `yaml:"httpsCertFile"`
	KeyFile      string                    `yaml:"httpsKeyFile"`
	BootstrapDNS Upstream                  `yaml:"bootstrapDns"`
}

// PrometheusConfig contains the config values for prometheus
type PrometheusConfig struct {
	Enable bool   `yaml:"enable"`
	Path   string `yaml:"path"`
}

type UpstreamConfig struct {
	ExternalResolvers []Upstream `yaml:"externalResolvers"`
}

type CustomDNSConfig struct {
	Mapping map[string]net.IP `yaml:"mapping"`
}

type ConditionalUpstreamConfig struct {
	Mapping map[string]Upstream `yaml:"mapping"`
}

type BlockingConfig struct {
	BlackLists        map[string][]string `yaml:"blackLists"`
	WhiteLists        map[string][]string `yaml:"whiteLists"`
	ClientGroupsBlock map[string][]string `yaml:"clientGroupsBlock"`
	BlockType         string              `yaml:"blockType"`
	RefreshPeriod     int                 `yaml:"refreshPeriod"`
}

type ClientLookupConfig struct {
	ClientnameIPMapping map[string][]net.IP `yaml:"clients"`
	Upstream            Upstream            `yaml:"upstream"`
	SingleNameOrder     []uint              `yaml:"singleNameOrder"`
}

type CachingConfig struct {
	MinCachingTime int `yaml:"minTime"`
	MaxCachingTime int `yaml:"maxTime"`
}

type QueryLogConfig struct {
	Dir              string `yaml:"dir"`
	PerClient        bool   `yaml:"perClient"`
	LogRetentionDays uint64 `yaml:"logRetentionDays"`
}

func NewConfig(path string) Config {
	cfg := Config{}
	setDefaultValues(&cfg)

	data, err := ioutil.ReadFile(path)

	if err != nil {
		log.Fatal("Can't read config file: ", err)
	}

	err = yaml.UnmarshalStrict(data, &cfg)
	if err != nil {
		log.Fatal("wrong file structure: ", err)
	}

	if cfg.LogFormat != CfgLogFormatText && cfg.LogFormat != CfgLogFormatJSON {
		log.Fatal("LogFormat should be 'text' or 'json'")
	}

	return cfg
}

func setDefaultValues(cfg *Config) {
	cfg.Port = cfgDefaultPort
	cfg.LogLevel = "info"
	cfg.LogFormat = CfgLogFormatText
	cfg.Prometheus.Path = cfgDefaultPrometheusPath
}
