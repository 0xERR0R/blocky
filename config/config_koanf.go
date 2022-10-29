package config

import (
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/mitchellh/mapstructure"
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
		textUnmarshallerHookFunc(),
		mapstructure.StringToIPHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		queryTypeHookFunc(),
		bootstrapConfigUnmarshallerHookFunc())
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
