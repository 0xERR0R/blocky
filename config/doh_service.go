package config

type DoHService struct {
	Addrs DoHAddrs `yaml:"addrs"`
}

type DoHAddrs struct {
	HTTPAddrs  `yaml:",inline"`
	HTTPSAddrs `yaml:",inline"`
}

type HTTPAddrs struct {
	HTTP ListenConfig `yaml:"http"`
}

type HTTPSAddrs struct {
	HTTPS ListenConfig `yaml:"https"`
}
