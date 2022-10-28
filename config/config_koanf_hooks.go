package config

import (
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
)

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

				for qi := 0; qi <= 110; qi++ {
					q := dns.Type(qi)
					if qt == q.String() {
						qtypes = append(qtypes, q)

						break
					}

					if qi == 110 {
						return nil, fmt.Errorf("unknown DNS query type: %s", qt)
					}
				}
			}

			return NewQTypeSet(qtypes...), nil
		}

		return data, nil
	}
}

func upstreamTypeHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() == reflect.String &&
			t == reflect.TypeOf(Upstream{}) {
			result, err := ParseUpstream(data.(string))

			return result, err
		}

		return data, nil
	}
}

func durationTypeHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() == reflect.String &&
			t == reflect.TypeOf(Duration(0)) {
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
		}

		return data, nil
	}
}
