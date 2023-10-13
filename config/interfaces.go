package config

// InterfacesConfig configuration for blocky's interfaces (REST, DoH, ...)
type InterfacesConfig struct {
	Rest RESTConfig `yaml:"rest"`
	DoH  DoHConfig  `yaml:"dns-over-http"`
}

type RESTConfig struct {
	Enable bool `yaml:"enable" default:"true"`
}

type DoHConfig struct {
	Enable bool `yaml:"enable" default:"true"`
}
