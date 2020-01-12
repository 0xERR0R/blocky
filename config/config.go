package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

// nolint:gochecknoglobals
var netDefaultPort = map[string]uint16{
	"udp":     53,
	"tcp":     53,
	"tcp-tls": 853,
}

// Upstream is the definition of external DNS server
type Upstream struct {
	Net  string
	Host string
	Port uint16
}

func (u *Upstream) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	upstream, err := parseUpstream(s)
	if err != nil {
		return err
	}

	*u = upstream

	return nil
}

// parseUpstream creates new Upstream from passed string in format net:host:port
func parseUpstream(upstream string) (result Upstream, err error) {
	if strings.Trim(upstream, " ") == "" {
		return Upstream{}, nil
	}

	parts := strings.Split(upstream, ":")

	if len(parts) < 2 || len(parts) > 3 {
		err = fmt.Errorf("wrong configuration, couldn't parse input '%s', please enter net:host[:port]", upstream)
		return
	}

	net := strings.TrimSpace(parts[0])

	if _, ok := netDefaultPort[net]; !ok {
		err = fmt.Errorf("wrong configuration, couldn't parse net '%s', please user one of %s",
			net, reflect.ValueOf(netDefaultPort).MapKeys())
		return
	}

	var port uint16

	host := strings.TrimSpace(parts[1])

	if len(parts) == 3 {
		var p int
		p, err = strconv.Atoi(strings.TrimSpace(parts[2]))

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
		port = netDefaultPort[net]
	}

	return Upstream{Net: net, Host: host, Port: port}, nil
}

// main configuration
type Config struct {
	Upstream     UpstreamConfig            `yaml:"upstream"`
	CustomDNS    CustomDNSConfig           `yaml:"customDNS"`
	Conditional  ConditionalUpstreamConfig `yaml:"conditional"`
	Blocking     BlockingConfig            `yaml:"blocking"`
	ClientLookup ClientLookupConfig        `yaml:"clientLookup"`
	QueryLog     QueryLogConfig            `yaml:"queryLog"`
	Port         uint16
	LogLevel     string `yaml:"logLevel"`
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
}

type ClientLookupConfig struct {
	Upstream        Upstream `yaml:"upstream"`
	SingleNameOrder []uint   `yaml:"singleNameOrder"`
}

type QueryLogConfig struct {
	Dir              string `yaml:"dir"`
	PerClient        bool   `yaml:"perClient"`
	LogRetentionDays uint64 `yaml:"logRetentionDays"`
}

func NewConfig() Config {
	cfg := Config{}
	data, err := ioutil.ReadFile("config.yml")

	if err != nil {
		log.Fatal("Can't read config file: ", err)
	}

	err = yaml.UnmarshalStrict(data, &cfg)
	if err != nil {
		log.Fatal("wrong file structure: ", err)
	}

	return cfg
}
