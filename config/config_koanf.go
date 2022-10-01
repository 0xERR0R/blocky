package config

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
	yamlv2 "gopkg.in/yaml.v2"
)

const prefix = "BLOCKY_"

func loadEnvironment(k *koanf.Koanf) error {
	return k.Load(env.Provider(prefix, "_", func(s string) string {
		return strings.TrimPrefix(s, prefix)
	}), nil)
}

func loadFile(k *koanf.Koanf, path string) error {
	return k.Load(file.Provider(path), yaml.Parser())
}

func unmarshalKoanf(k *koanf.Koanf, cfg *Config) error {
	err := k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook:       composeDecodeHookFunc(),
			Metadata:         nil,
			Result:           &cfg,
			WeaklyTypedInput: true,
		},
	})

	return err
}

func composeDecodeHookFunc() mapstructure.DecodeHookFunc {
	return mapstructure.ComposeDecodeHookFunc(
		mapToSliceHookFunc(),
		upstreamTypeHookFunc(),
		durationTypeHookFunc(),
		mapstructure.TextUnmarshallerHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		queryTypeHookFunc(),
		unmarshalYAMLHookFunc())
}

func unmarshalYAMLHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String ||
			t == reflect.TypeOf(Upstream{}) {
			return data, nil
		}

		result := reflect.New(t).Interface()
		unmarshaller, ok := result.(yamlv2.Unmarshaler)
		if !ok {
			return data, nil
		}

		err := unmarshaller.UnmarshalYAML(func(v interface{}) error {
			vt := reflect.TypeOf(v)
			val := reflect.ValueOf(v)
			if vt == reflect.TypeOf(&Upstream{}) {
				result, err := ParseUpstream(data.(string))
				if err != nil {
					return err
				}
				val.Elem().Set(reflect.ValueOf(result))
			} else {
				val.Elem().Set(reflect.ValueOf(data))
			}
			return nil
		})

		if err != nil {
			return data, err
		}

		return result, nil
	}
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

func mapToSliceHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {

		if f.Kind() == reflect.Map {
			unboxed, ok := data.(map[string]interface{})
			if ok && unboxed != nil {
				res, ok := extract(unboxed)
				if ok {
					return res, nil
				}
			}
		}

		return data, nil
	}
}

func extract(in map[string]interface{}) ([]interface{}, bool) {
	res := make([]interface{}, 0, len(in))
	keys := make([]int, 0, len(in))
	intmap := make(map[int]interface{})
	for k, v := range in {
		ik, err := strconv.Atoi(k)
		if err != nil {
			return res, false
		}
		keys = append(keys, ik)
		intmap[ik] = v
	}
	sort.Ints(keys)
	for _, k := range keys {
		res = append(res, intmap[k])
	}

	return res, true
}
