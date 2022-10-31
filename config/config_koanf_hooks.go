package config

import (
	"encoding"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
)

// nolint:gochecknoglobals
var (
	koanfHookTypes = []reflect.Type{
		reflect.TypeOf(Duration(0)),
		reflect.TypeOf(Upstream{}),
		reflect.TypeOf(QTypeSet{}),
	}
)

const (
	queryTypeMax = 110
)

func hasCustomHook(t reflect.Type) bool {
	for _, kht := range koanfHookTypes {
		if kht == t {
			return true
		}
	}

	return false
}

func queryTypeHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() == reflect.Slice &&
			t == reflect.TypeOf(QTypeSet{}) {
			s := reflect.ValueOf(data)

			var qtypes []dns.Type

			for i := 0; i < s.Len(); i++ {
				qt := fmt.Sprint(s.Index(i))

				for qi := 0; qi <= queryTypeMax; qi++ {
					q := dns.Type(qi)
					if qt == q.String() {
						qtypes = append(qtypes, q)

						break
					}

					if qi == queryTypeMax {
						return nil, fmt.Errorf("unknown DNS query type: %s", qt)
					}
				}
			}

			return NewQTypeSet(qtypes...), nil
		}

		return data, nil
	}
}

// upstreamTypeHookFunc creates Upstream from mapstructure
func upstreamTypeHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() == reflect.String &&
			t == reflect.TypeOf(Upstream{}) {
			return ParseUpstream(data.(string))
		}

		return data, nil
	}
}

// durationTypeHookFunc creates Duration from mapstructure. If no unit is used, uses minutes
func durationTypeHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		dt := reflect.TypeOf(Duration(0))
		if t == dt && f.Kind() == reflect.String {
			input := data.(string)
			if minutes, err := strconv.Atoi(input); err == nil {
				// duration is defined as number without unit
				// use minutes to ensure back compatibility
				result := Duration(time.Duration(minutes) * time.Minute)

				return result, nil
			}

			duration, err := time.ParseDuration(input)
			if err == nil {
				result := Duration(duration)

				return result, nil
			}
		} else if t == dt && f.Kind() == reflect.Int {
			// duration is defined as number without unit
			// use minutes to ensure back compatibility
			minutes := data.(int)

			result := Duration(time.Duration(minutes) * time.Minute)

			return result, nil
		}

		return data, nil
	}
}

// UnmarshalYAML creates BootstrapConfig from YAML
func bootstrapConfigUnmarshallerHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() == reflect.String &&
			t == reflect.TypeOf(BootstrapConfig{}) {
			up, err := ParseUpstream(data.(string))
			if err != nil {
				return nil, err
			}

			return BootstrapConfig{
				Upstream: up,
			}, nil
		}

		return data, nil
	}
}

func textUnmarshallerHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if hasCustomHook(t) || f.Kind() != reflect.String {
			return data, nil
		}

		result := reflect.New(t).Interface()

		unmarshaller, ok := result.(encoding.TextUnmarshaler)

		if !ok {
			return data, nil
		}

		if err := unmarshaller.UnmarshalText([]byte(data.(string))); err != nil {
			return nil, err
		}

		return result, nil
	}
}
