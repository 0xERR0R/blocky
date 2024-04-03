package config

type (
	DoHService     HTTPService
	MetricsService HTTPService
)

// HTTPService can be used by any service that uses HTTP(S).
type HTTPService struct {
	Addrs AllHTTPAddrs `yaml:"addrs"`
}

type AllHTTPAddrs struct {
	HTTPAddrs  `yaml:",inline"`
	HTTPSAddrs `yaml:",inline"`
}

type HTTPAddrs struct {
	HTTP ListenConfig `yaml:"http"`
}

type HTTPSAddrs struct {
	HTTPS ListenConfig `yaml:"https"`
}
