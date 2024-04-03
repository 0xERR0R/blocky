package config

type (
	APIService     httpService
	DoHService     httpService
	MetricsService httpService
)

// httpService can be used by any service that uses HTTP(S).
type httpService struct {
	Addrs httpAddrs `yaml:"addrs"`
}

type httpAddrs struct {
	HTTPAddrs  `yaml:",inline"`
	HTTPSAddrs `yaml:",inline"`
}

type HTTPAddrs struct {
	HTTP ListenConfig `yaml:"http"`
}

type HTTPSAddrs struct {
	HTTPS ListenConfig `yaml:"https"`
}
