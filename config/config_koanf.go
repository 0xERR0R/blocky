package config

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/env"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v2"
)

const prefix = "BLOCKY_"

func loadEnvironment(cfg *Config) (*Config, error) {
	var k = koanf.New("_")
	err := k.Load(env.Provider(prefix, "_", func(s string) string {
		//return strings.ToLower(strings.TrimPrefix(s, prefix))
		return strings.TrimPrefix(s, prefix)
	}), nil)

	if err != nil {
		return nil, err
	}

	var test interface{}

	err = k.UnmarshalWithConf("", &test, koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook:       composeDecodeHookFunc(),
			Metadata:         nil,
			Result:           &cfg,
			WeaklyTypedInput: true,
		},
	})

	fmt.Println(test)

	return cfg, err
}

func composeDecodeHookFunc() mapstructure.DecodeHookFunc {
	return mapstructure.ComposeDecodeHookFunc(
		mapToSliceHookFunc(),
		mapstructure.TextUnmarshallerHookFunc(),
		mapstructure.StringToIPHookFunc(),
		mapstructure.StringToIPNetHookFunc(),
		unmarshalYAMLHookFunc())
}

func unmarshalYAMLHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}

		result := reflect.New(t).Interface()
		unmarshaller, ok := result.(yaml.Unmarshaler)
		if !ok {
			return data, nil
		}

		err := unmarshaller.UnmarshalYAML(func(v interface{}) error {
			val := reflect.ValueOf(v)
			val.Elem().Set(reflect.ValueOf(data))
			return nil
		})

		if err != nil {
			return data, err
		}

		return result, nil
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
