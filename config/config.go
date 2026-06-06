//go:generate go tool go-enum -f=$GOFILE --marshal --names --values --template ../tools/schemagen/templates/enum_description.tmpl
//go:generate go run ../tools/schemagen
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
	"github.com/0xERR0R/blocky/config/schema"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"
	"github.com/creasty/defaults"
	"gopkg.in/yaml.v2"
)

const (
	udpPort   = 53
	tlsPort   = 853
	httpsPort = 443
	quicPort  = 853

	secretObfuscator = "********"
)

type Configurable interface {
	// IsEnabled returns true when the receiver is configured.
	IsEnabled() bool

	// LogConfig logs the receiver's configuration.
	//
	// The behavior of this method is undefined when `IsEnabled` returns false.
	LogConfig(logger *logrus.Entry)
}

// NetProtocol resolver protocol ENUM(
// tcp+udp // TCP and UDP protocols
// tcp-tls // TCP-TLS protocol
// https // HTTPS protocol
// quic // DNS-over-QUIC protocol
// )
type NetProtocol uint16

// IPVersion represents IP protocol version(s). ENUM(
// dual // Use both IPv4 and IPv6.
// v4 // Use IPv4 only.
// v6 // Use IPv6 only.
// )
type IPVersion uint8

func (ipv IPVersion) Net() string {
	if net, ok := ipVersionNets[ipv]; ok {
		return net
	}

	panic(fmt.Errorf("bad value: %s", ipv))
}

func (ipv IPVersion) QTypes() []dns.Type {
	if qtypes, ok := ipVersionQTypes[ipv]; ok {
		return qtypes
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
// console // Log to console output (used when no type is set).
// none // Do not log any queries.
// mysql // Log each query to an external MySQL or MariaDB database.
// postgresql // Log each query to an external PostgreSQL database.
// csv // Log to a CSV file (one per day).
// csv-client // Log to a CSV file (one per day and per client).
// timescale // Log each query to an external Timescale database.
// sqlite // Log each query to a local SQLite database file.
// )
type QueryLogType int16

// InitStrategy startup strategy ENUM(
// blocking // Initialization runs before DNS resolution starts; errors are logged but Blocky keeps running if possible.
// failOnError // Like blocking but Blocky exits with an error if initialization fails.
// fast // Blocky serves DNS immediately and runs initialization in the background.
// )
type InitStrategy uint16

func (s InitStrategy) Do(ctx context.Context, init func(context.Context) error, logErr func(error)) error {
	init = recoverToError(init, func(panicVal any) error {
		return fmt.Errorf("panic during initialization: %v", panicVal)
	})

	if s == InitStrategyFast {
		go func() {
			err := init(ctx)
			if err != nil {
				logErr(err)
			}
		}()

		return nil
	}

	err := init(ctx)
	if err != nil {
		logErr(err)

		if s == InitStrategyFailOnError {
			return fmt.Errorf("initialization failed with strategy %s: %w", s, err)
		}
	}

	return nil
}

// QueryLogField data field to be logged
// ENUM(clientIP,clientName,responseReason,responseAnswer,question,duration)
type QueryLogField string

// UpstreamStrategy upstream server usage strategy ENUM(
// parallel_best // Picks 2 random weighted resolvers per query and returns the fastest answer (default).
// strict // Queries upstreams in strict order; the next is tried only if the previous fails.
// random // Picks one random weighted resolver per query; another is tried on failure.
// )
type UpstreamStrategy uint8

//nolint:gochecknoglobals
var netDefaultPort = map[NetProtocol]uint16{
	NetProtocolTcpUdp: udpPort,
	NetProtocolTcpTls: tlsPort,
	NetProtocolHttps:  httpsPort,
	NetProtocolQuic:   quicPort,
}

//nolint:gochecknoglobals
var ipVersionNets = map[IPVersion]string{
	IPVersionDual: "ip",
	IPVersionV4:   "ip4",
	IPVersionV6:   "ip6",
}

//nolint:gochecknoglobals
var ipVersionQTypes = map[IPVersion][]dns.Type{
	IPVersionDual: {dns.Type(dns.TypeA), dns.Type(dns.TypeAAAA)},
	IPVersionV4:   {dns.Type(dns.TypeA)},
	IPVersionV6:   {dns.Type(dns.TypeAAAA)},
}

// ListenConfig is a list of address(es) to listen on
type ListenConfig []string

// UnmarshalText implements `encoding.TextUnmarshaler`.
func (l *ListenConfig) UnmarshalText(data []byte) error {
	addresses := string(data)

	*l = strings.Split(addresses, ",")

	l.prefixPorts()

	return nil
}

// UnmarshalYAML creates a ListenConfig from YAML
func (l *ListenConfig) UnmarshalYAML(unmarshal func(any) error) error {
	// Try parsing as a native YAML array...
	if unmarshal((*[]string)(l)) == nil {
		l.prefixPorts()

		return nil
	}

	// ...if it fails, it should be a comma separated string
	var str string

	if err := unmarshal(&str); err != nil {
		return fmt.Errorf("failed to unmarshal listen config: %w", err)
	}

	return l.UnmarshalText([]byte(str))
}

// prefixPorts ensures all ports have a : prefix
func (l *ListenConfig) prefixPorts() {
	for i, addr := range *l {
		if !strings.ContainsRune(addr, ':') {
			(*l)[i] = ":" + addr
		}
	}
}

// UnmarshalYAML creates BootstrapDNS from YAML
func (b *BootstrapDNS) UnmarshalYAML(unmarshal func(any) error) error {
	var single BootstrappedUpstream
	if err := unmarshal(&single); err == nil {
		*b = BootstrapDNS{single}

		return nil
	}

	// bootstrapDNS is used to avoid infinite recursion:
	// if we used BootstrapDNS, unmarshal would just call us again.
	var c bootstrapDNS
	if err := unmarshal(&c); err != nil {
		return fmt.Errorf("failed to unmarshal bootstrap DNS configuration: %w", err)
	}

	*b = BootstrapDNS(c)

	return nil
}

// UnmarshalYAML creates BootstrappedUpstream from YAML
func (b *BootstrappedUpstream) UnmarshalYAML(unmarshal func(any) error) error {
	if err := unmarshal(&b.Upstream); err == nil {
		return nil
	}

	// bootstrappedUpstream is used to avoid infinite recursion:
	// if we used BootstrappedUpstream, unmarshal would just call us again.
	var c bootstrappedUpstream
	if err := unmarshal(&c); err != nil {
		return fmt.Errorf("failed to unmarshal bootstrapped upstream configuration: %w", err)
	}

	*b = BootstrappedUpstream(c)

	return nil
}

// Config main configuration
type Config struct {
	// Upstream DNS servers and strategy configuration.
	Upstreams Upstreams `yaml:"upstreams"`
	// IP version used for outgoing connections (dual, v4, v6).
	ConnectIPVersion IPVersion `yaml:"connectIPVersion"`
	// Custom static DNS mappings and zone definitions.
	CustomDNS CustomDNS `yaml:"customDNS"`
	// Conditional upstream resolvers for specific domains.
	Conditional ConditionalUpstream `yaml:"conditional"`
	// Blocking configuration with allow/denylists and client groups.
	Blocking Blocking `yaml:"blocking"`
	// Client name lookup configuration for resolving client identifiers.
	ClientLookup ClientLookup `yaml:"clientLookup"`
	// DNS response caching settings.
	Caching Caching `yaml:"caching"`
	// Query logging configuration.
	QueryLog QueryLog `yaml:"queryLog"`
	// Prometheus metrics configuration.
	Prometheus Metrics `yaml:"prometheus"`
	// Redis configuration for cache and state synchronization between instances.
	Redis Redis `yaml:"redis"`
	// Logging configuration.
	Log log.Config `yaml:"log"`
	// Listen addresses for DNS, HTTP, HTTPS, and TLS.
	Ports Ports `yaml:"ports"`
	// Minimum TLS version the DoT and DoH servers use to serve encrypted DNS requests.
	MinTLSServeVer TLSVersion `default:"1.2" yaml:"minTlsServeVersion"`
	// Path to the TLS certificate file for DoH and DoT; if empty, a self-signed certificate is generated.
	CertFile string `yaml:"certFile"`
	// Path to the TLS key file for DoH and DoT; if empty, a self-signed certificate is generated.
	KeyFile string `yaml:"keyFile"`
	// Bootstrap DNS servers used to resolve DoH/DoT upstream hostnames.
	BootstrapDNS BootstrapDNS `yaml:"bootstrapDns"`
	// Local hosts file resolution settings.
	HostsFile HostsFile `yaml:"hostsFile"`
	// When enabled, blocky returns NXDOMAIN immediately for non-FQDN queries.
	FQDNOnly FQDNOnly `yaml:"fqdnOnly"`
	// DNS query type filtering configuration.
	Filtering Filtering `yaml:"filtering"`
	// Extended DNS Errors (RFC 8914) configuration.
	EDE EDE `yaml:"ede"`
	// EDNS Client Subnet options.
	ECS ECS `yaml:"ecs"`
	// Special Use Domain Names (SUDN) blocking configuration.
	SUDN SUDN `yaml:"specialUseDomains"`
	// DNS64 synthesis configuration for IPv6-only clients (RFC 6147).
	DNS64 DNS64 `yaml:"dns64"`
	// DNSSEC validation configuration.
	DNSSEC DNSSEC `yaml:"dnssec"`
	// HTTP/3 (DoH3) server configuration.
	HTTP3 HTTP3 `yaml:"http3"`
	// Per-client DNS query rate limiting configuration.
	RateLimit RateLimit `yaml:"rateLimit"`

	// Deprecated options
	Deprecated struct {
		Upstream            *UpstreamGroups `yaml:"upstream"`
		UpstreamTimeout     *Duration       `yaml:"upstreamTimeout"`
		DisableIPv6         *bool           `yaml:"disableIPv6"`
		LogLevel            *logrus.Level   `yaml:"logLevel"`
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

type Ports struct {
	// Listen address(es) for DNS over TCP and UDP (default: 53).
	DNS ListenConfig `default:"53" yaml:"dns"`
	// Listen address(es) for HTTP (metrics, REST API, DoH).
	HTTP ListenConfig `yaml:"http"`
	// Listen address(es) for HTTPS (metrics, REST API, DoH).
	HTTPS ListenConfig `yaml:"https"`
	// Listen address(es) for DNS-over-TLS (DoT).
	TLS ListenConfig `yaml:"tls"`
	// URL path for DoH queries.
	DOHPath string `default:"/dns-query" yaml:"dohPath"`
	// Allow binding the DNS and DoT listeners to addresses that are not yet assigned to a network
	// interface, via the Linux IP_FREEBIND socket option (e.g. for Tailscale/WireGuard/VRRP addresses
	// brought up after startup). Has no effect on wildcard binds and is ignored, with a warning, on
	// non-Linux platforms.
	FreeBind bool `default:"false" yaml:"freeBind"`
}

func (c *Ports) LogConfig(logger *logrus.Entry) {
	logger.Infof("DNS      = %s", c.DNS)
	logger.Infof("TLS      = %s", c.TLS)
	logger.Infof("HTTP     = %s", c.HTTP)
	logger.Infof("HTTPS    = %s", c.HTTPS)
	logger.Infof("DOHPath  = %s", c.DOHPath)
	logger.Infof("FreeBind = %t", c.FreeBind)
}

func (c *Ports) validate() error {
	if c.DOHPath == "" {
		return errors.New("dohPath must not be empty")
	}

	if !strings.HasPrefix(c.DOHPath, "/") {
		return fmt.Errorf("dohPath must start with '/', got %q", c.DOHPath)
	}

	if strings.ContainsAny(c.DOHPath, " \t") {
		return fmt.Errorf("dohPath must not contain whitespace, got %q", c.DOHPath)
	}

	if strings.Contains(c.DOHPath, "?") {
		return fmt.Errorf("dohPath must not contain '?', got %q", c.DOHPath)
	}

	if strings.Contains(c.DOHPath, "#") {
		return fmt.Errorf("dohPath must not contain '#', got %q", c.DOHPath)
	}

	return nil
}

// privilegedPortCeiling is the first non-privileged TCP/UDP port. Ports below
// it require CAP_NET_BIND_SERVICE (or root) to bind on Linux.
const privilegedPortCeiling = 1024

// PrivilegedPorts returns the configured listen addresses across DNS, HTTP,
// HTTPS and TLS whose port is below privilegedPortCeiling.
func (p *Ports) PrivilegedPorts() []string {
	var privileged []string

	for _, lc := range []ListenConfig{p.DNS, p.HTTP, p.HTTPS, p.TLS} {
		for _, addr := range lc {
			// Port 0 (OS-assigned ephemeral port) is never privileged.
			if port, ok := extractPort(addr); ok && port > 0 && port < privilegedPortCeiling {
				privileged = append(privileged, addr)
			}
		}
	}

	return privileged
}

// extractPort returns the port number of a listen address. It accepts every
// ListenConfig form: "53", ":53", "1.2.3.4:53", "[::1]:853", "host:5353".
func extractPort(addr string) (uint16, bool) {
	if addr == "" {
		return 0, false
	}

	portStr := addr
	if _, splitPort, err := net.SplitHostPort(addr); err == nil {
		portStr = splitPort
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, false
	}

	return uint16(port), true
}

// split in two types to avoid infinite recursion. See `BootstrapDNS.UnmarshalYAML`.
type (
	BootstrapDNS bootstrapDNS
	bootstrapDNS []BootstrappedUpstream
)

func (b *BootstrapDNS) IsEnabled() bool {
	return len(*b) != 0
}

func (b *BootstrapDNS) LogConfig(*logrus.Entry) {
	// This should not be called, at least for now:
	// The Boostrap resolver is not in the chain and thus its config is not logged
	panic("not implemented")
}

// split in two types to avoid infinite recursion. See `BootstrappedUpstream.UnmarshalYAML`.
type (
	BootstrappedUpstream bootstrappedUpstream
	bootstrappedUpstream struct {
		Upstream Upstream `yaml:"upstream"`
		IPs      []net.IP `yaml:"ips"`
		// Optional: read bootstrap nameservers from a resolv.conf(5) file at this path instead of listing them inline.
		ResolvFile string `yaml:"resolvFile"`
	}
)

type (
	FQDNOnly = toEnable
	EDE      = toEnable
)

type toEnable struct {
	Enable bool `default:"false" yaml:"enable"`
}

// IsEnabled implements `config.Configurable`.
func (c *toEnable) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *toEnable) LogConfig(logger *logrus.Entry) {
	logger.Info("enabled")
}

type Init struct {
	// Startup strategy controlling how initialization failures are handled.
	Strategy InitStrategy `default:"blocking" yaml:"strategy"`
}

func (c *Init) LogConfig(logger *logrus.Entry) {
	logger.Debugf("strategy = %s", c.Strategy)
}

type SourceLoading struct {
	Init `yaml:",inline"`

	// Maximum number of sources downloaded and processed concurrently (default: 4).
	Concurrency uint `default:"4" yaml:"concurrency"`
	// Maximum parse errors per source before the source is considered invalid; -1 disables the limit.
	MaxErrorsPerSource int `default:"5" yaml:"maxErrorsPerSource"`
	// How often sources are reloaded; a value of 0 or less disables periodic refresh (default: 4h).
	RefreshPeriod Duration `default:"4h" yaml:"refreshPeriod"`
	// HTTP(S) download settings for remote sources.
	Downloads Downloader `yaml:"downloads"`
}

func (c *SourceLoading) LogConfig(logger *logrus.Entry) {
	c.Init.LogConfig(logger)
	logger.Infof("concurrency = %d", c.Concurrency)
	logger.Debugf("maxErrorsPerSource = %d", c.MaxErrorsPerSource)

	if c.RefreshPeriod.IsAboveZero() {
		logger.Infof("refresh = every %s", c.RefreshPeriod)
	} else {
		logger.Debug("refresh = disabled")
	}

	logger.Info("downloads:")
	log.WithIndent(logger, "  ", c.Downloads.LogConfig)
}

func (c *SourceLoading) StartPeriodicRefresh(
	ctx context.Context, refresh func(context.Context) error, logErr func(error),
) error {
	err := c.Strategy.Do(ctx, refresh, logErr)
	if err != nil {
		return fmt.Errorf("failed to start periodic refresh: %w", err)
	}

	if c.RefreshPeriod > 0 {
		go c.periodically(ctx, refresh, logErr)
	}

	return nil
}

func (c *SourceLoading) periodically(
	ctx context.Context, refresh func(context.Context) error, logErr func(error),
) {
	refresh = recoverToError(refresh, func(panicVal any) error {
		return fmt.Errorf("panic during refresh: %v", panicVal)
	})

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

func recoverToError(do func(context.Context) error, onPanic func(any) error) func(context.Context) error {
	return func(ctx context.Context) (rerr error) {
		defer func() {
			if val := recover(); val != nil {
				rerr = onPanic(val)
			}
		}()

		return do(ctx)
	}
}

type Downloader struct {
	// Timeout per download attempt (default: 5s).
	Timeout Duration `default:"5s" yaml:"timeout"`
	// Timeout for reading the download response body (default: 20s).
	ReadTimeout Duration `default:"20s" yaml:"readTimeout"`
	// Timeout for reading the download response headers (default: 20s).
	ReadHeaderTimeout Duration `default:"20s" yaml:"readHeaderTimeout"`
	// Timeout for writing the downloaded file (default: 20s).
	WriteTimeout Duration `default:"20s" yaml:"writeTimeout"`
	// Number of download attempts before giving up (default: 3).
	Attempts uint `default:"3" yaml:"attempts"`
	// Pause between consecutive download attempts (default: 500ms).
	Cooldown Duration `default:"500ms" yaml:"cooldown"`
	// Directory for the on-disk download cache. When empty (default), downloads are
	// fully stateless: nothing is written to disk and every source is downloaded in
	// full on every refresh. When set, blocky uses HTTP conditional requests and
	// serves unchanged/unavailable sources from this directory.
	CachePath string `yaml:"cachePath"`
}

func (c *Downloader) LogConfig(logger *logrus.Entry) {
	logger.Infof("timeout = %s", c.Timeout)
	logger.Infof("attempts = %d", c.Attempts)
	logger.Debugf("cooldown = %s", c.Cooldown)

	if c.CachePath != "" {
		logger.Infof("cachePath = %s", c.CachePath)
	} else {
		logger.Debug("cachePath = (disabled, stateless downloads)")
	}
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
	logger := logrus.NewEntry(log.Log())

	return loadConfig(logger, path, mandatory)
}

func loadConfig(logger *logrus.Entry, path string, mandatory bool) (rCfg *Config, rerr error) {
	cfg, err := WithDefaults[Config]()
	if err != nil {
		return nil, fmt.Errorf("failed to apply default configuration: %w", err)
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

	var (
		data       []byte
		prettyPath string
	)

	if fs.IsDir() {
		prettyPath = filepath.Join(path, "*")

		data, err = readFromDir(path, data)
		if err != nil {
			return nil, fmt.Errorf("can't read config files: %w", err)
		}
	} else {
		prettyPath = path

		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("can't read config file: %w", err)
		}
	}

	cfg.CustomDNS.Zone.configPath = prettyPath

	err = unmarshalConfig(logger, data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config from %s: %w", prettyPath, err)
	}

	if err := cfg.Ports.validate(); err != nil {
		logger.Fatal(err)
	}

	// Normalize rewrite keys to lowercase after unmarshaling
	cfg.CustomDNS.NormalizeRewrites()
	cfg.Conditional.NormalizeRewrites()

	return &cfg, nil
}

// isYAMLFile checks if a file path has a YAML extension (.yml or .yaml)
func isYAMLFile(filePath string) bool {
	return strings.HasSuffix(filePath, ".yml") || strings.HasSuffix(filePath, ".yaml")
}

func readFromDir(path string, data []byte) ([]byte, error) {
	err := filepath.WalkDir(path, func(filePath string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing %s: %w", filePath, err)
		}

		if path == filePath {
			return nil
		}

		// Ignore non YAML files
		if !isYAMLFile(filePath) {
			return nil
		}

		isRegular, err := isRegularFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", filePath, err)
		}

		// Ignore non regular files (directories, sockets, etc.)
		if !isRegular {
			return nil
		}

		fileData, err := os.ReadFile(filePath) //nolint:gosec // config dir is admin-controlled; TOCTOU risk is acceptable
		if err != nil {
			return fmt.Errorf("failed to read config file %s: %w", filePath, err)
		}

		data = append(data, []byte("\n")...)
		data = append(data, fileData...)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", path, err)
	}

	return data, nil
}

// isRegularFile follows symlinks, so the result is `true` for a symlink to a regular file.
func isRegularFile(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("failed to stat %s: %w", path, err)
	}

	isRegular := stat.Mode()&os.ModeType == 0

	return isRegular, nil
}

func unmarshalConfig(logger *logrus.Entry, data []byte, cfg *Config) error {
	err := yaml.UnmarshalStrict(data, cfg)
	if err != nil {
		// Enrich the already-failing path with field-path schema errors,
		// keeping the underlying yaml error for detail. This never rejects a
		// config blocky would accept: we only reach here because
		// UnmarshalStrict already failed.
		if schemaErrs, sErr := schema.ValidateYAML(data); sErr == nil && len(schemaErrs) > 0 {
			return fmt.Errorf("wrong file structure: %w\n%s", err, formatSchemaErrors(schemaErrs))
		}

		return fmt.Errorf("wrong file structure: %w", err)
	}

	// Success path: the schema disagreeing here is a potential gap in the
	// schema, never a config error. Warn, never fail.
	if schemaErrs, sErr := schema.ValidateYAML(data); sErr == nil && len(schemaErrs) > 0 {
		for _, e := range schemaErrs {
			logger.Warnf("config does not match schema (possible schema gap, please report): %s", e)
		}
	}

	usesDepredOpts := cfg.migrate(logger)
	if usesDepredOpts {
		logger.Error("configuration uses deprecated options, see warning logs for details")
	}

	cfg.validate(logger)

	return nil
}

// formatSchemaErrors renders schema findings as an indented bullet list.
func formatSchemaErrors(errs []schema.Error) string {
	lines := make([]string, 0, len(errs))
	for _, e := range errs {
		lines = append(lines, "  - "+e.String())
	}

	return strings.Join(lines, "\n")
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
		"port":         Move(To("ports.dns", &cfg.Ports)),
		"httpPort":     Move(To("ports.http", &cfg.Ports)),
		"httpsPort":    Move(To("ports.https", &cfg.Ports)),
		"tlsPort":      Move(To("ports.tls", &cfg.Ports)),
		"logLevel":     Move(To("log.level", &cfg.Log)),
		"logFormat":    Move(To("log.format", &cfg.Log)),
		"logPrivacy":   Move(To("log.privacy", &cfg.Log)),
		"logTimestamp": Move(To("log.timestamp", &cfg.Log)),
		"dohUserAgent": Move(To("upstreams.userAgent", &cfg.Upstreams)),
		"startVerifyUpstream": Apply(To("upstreams.init.strategy", &cfg.Upstreams.Init), func(value bool) {
			if value {
				cfg.Upstreams.Init.Strategy = InitStrategyFailOnError
			} else {
				cfg.Upstreams.Init.Strategy = InitStrategyFast
			}
		}),
	})

	usesDepredOpts = cfg.Blocking.migrate(logger) || usesDepredOpts
	usesDepredOpts = cfg.HostsFile.migrate(logger) || usesDepredOpts

	return usesDepredOpts
}

func (cfg *Config) validate(logger *logrus.Entry) {
	cfg.MinTLSServeVer.validate(logger)
	cfg.Upstreams.validate(logger)

	// Blocking validation
	if err := cfg.Blocking.validate(); err != nil {
		logger.Warn(err)
	}

	// DNS64 validation
	if err := cfg.DNS64.validate(logger, &cfg.Filtering, &cfg.Caching); err != nil {
		logger.Fatal(err)
	}

	if err := cfg.RateLimit.validate(); err != nil {
		logger.Fatal(err)
	}
}

// ConvertPort converts string representation into a valid port (0 - 65535)
func ConvertPort(in string) (uint16, error) {
	const (
		base    = 10
		bitSize = 16
	)

	p, err := strconv.ParseUint(strings.TrimSpace(in), base, bitSize)
	if err != nil {
		return 0, fmt.Errorf("invalid port number '%s': %w", in, err)
	}

	return uint16(p), nil
}
