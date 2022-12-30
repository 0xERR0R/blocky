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

//nolint:gochecknoglobals
var (
	koanfHookTypes = []reflect.Type{
		reflect.TypeOf(Duration(0)),
		reflect.TypeOf(Upstream{}),
		reflect.TypeOf(QTypeSet{}),
	}
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
		data interface{},
	) (interface{}, error) {
		if f.Kind() == reflect.Slice &&
			t == reflect.TypeOf(QTypeSet{}) {
			s := reflect.ValueOf(data).Interface().([]any)

			var qtypes []dns.Type

			for _, q := range s {
				qt := q.(string)
				if qi, ok := dns.StringToType[qt]; ok {
					q := dns.Type(qi)
					qtypes = append(qtypes, q)
				} else {
					return nil, fmt.Errorf("unknown DNS query type: %s", qt)
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
		data interface{},
	) (interface{}, error) {
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
		data interface{},
	) (interface{}, error) {
		dt := reflect.TypeOf(Duration(0))
		if t != dt {
			return data, nil
		}

		//nolint:exhaustive
		switch f.Kind() {
		case reflect.String:
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

		case reflect.Int:
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
		data interface{},
	) (interface{}, error) {
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
		data interface{},
	) (interface{}, error) {
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
