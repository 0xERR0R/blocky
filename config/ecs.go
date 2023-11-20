package config

import (
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
)

const (
	ecsIpv4MaskMax = uint8(32)
	ecsIpv6MaskMax = uint8(128)
)

// ECSv4Mask is the subnet mask to be added as EDNS0 option for IPv4
type ECSv4Mask uint8

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (x *ECSv4Mask) UnmarshalText(text []byte) error {
	res, err := unmarshalInternal(text, ecsIpv4MaskMax, "IPv4")
	if err != nil {
		return err
	}

	*x = ECSv4Mask(res)

	return nil
}

// ECSv6Mask is the subnet mask to be added as EDNS0 option for IPv6
type ECSv6Mask uint8

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (x *ECSv6Mask) UnmarshalText(text []byte) error {
	res, err := unmarshalInternal(text, ecsIpv6MaskMax, "IPv6")
	if err != nil {
		return err
	}

	*x = ECSv6Mask(res)

	return nil
}

// ECS is the configuration of the ECS resolver
type ECS struct {
	UseAsClient bool      `yaml:"useAsClient" default:"false"`
	Forward     bool      `yaml:"forward" default:"false"`
	IPv4Mask    ECSv4Mask `yaml:"ipv4Mask" default:"0"`
	IPv6Mask    ECSv6Mask `yaml:"ipv6Mask" default:"0"`
}

// IsEnabled returns true if the ECS resolver is enabled
func (c *ECS) IsEnabled() bool {
	return c.UseAsClient || c.Forward || c.IPv4Mask > 0 || c.IPv6Mask > 0
}

// LogConfig logs the configuration
func (c *ECS) LogConfig(logger *logrus.Entry) {
	logger.Infof("Use as client = %t", c.UseAsClient)
	logger.Infof("Forward       = %t", c.Forward)
	logger.Infof("IPv4 netmask  = %d", c.IPv4Mask)
	logger.Infof("IPv6 netmask  = %d", c.IPv6Mask)
}

// unmarshalInternal unmarshals the subnet mask from the given text and checks if the value is valid
// it is used by the UnmarshalText methods of ECSv4Mask and ECSv6Mask
func unmarshalInternal(text []byte, maxvalue uint8, name string) (uint8, error) {
	strVal := string(text)

	uiVal, err := strconv.ParseUint(strVal, 10, 8)
	if err != nil {
		return 0, err
	}

	if uiVal > uint64(maxvalue) {
		return 0, fmt.Errorf("mask value (%s) is too large for %s(max: %d)", strVal, name, maxvalue)
	}

	return uint8(uiVal), nil
}
