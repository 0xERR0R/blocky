package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/exp/maps"
)

type QTypeSet map[QType]struct{}

func NewQTypeSet(qTypes ...dns.Type) QTypeSet {
	s := make(QTypeSet, len(qTypes))

	for _, qType := range qTypes {
		s.Insert(qType)
	}

	return s
}

func (s QTypeSet) Contains(qType dns.Type) bool {
	_, found := s[QType(qType)]

	return found
}

func (s *QTypeSet) Insert(qType dns.Type) {
	if *s == nil {
		*s = make(QTypeSet, 1)
	}

	(*s)[QType(qType)] = struct{}{}
}

func (s *QTypeSet) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input []QType
	if err := unmarshal(&input); err != nil {
		return err
	}

	*s = make(QTypeSet, len(input))

	for _, qType := range input {
		(*s)[qType] = struct{}{}
	}

	return nil
}

type QType dns.Type

func (c QType) String() string {
	return dns.Type(c).String()
}

// UnmarshalText implements `encoding.TextUnmarshaler`.
func (c *QType) UnmarshalText(data []byte) error {
	input := string(data)

	t, found := dns.StringToType[input]
	if !found {
		types := maps.Keys(dns.StringToType)

		sort.Strings(types)

		return fmt.Errorf("unknown DNS query type: '%s'. Please use following types '%s'",
			input, strings.Join(types, ", "))
	}

	*c = QType(t)

	return nil
}
