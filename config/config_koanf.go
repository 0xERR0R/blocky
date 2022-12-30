package config

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/0xERR0R/blocky/environment"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/mitchellh/mapstructure"
)

func loadEnvironment(k *koanf.Koanf) error {
	return k.Load(env.Provider(environment.EnvConfigPrefix, "_", func(s string) string {
		return strings.TrimPrefix(s, environment.EnvConfigPrefix)
	}), nil)
}

func loadFile(k *koanf.Koanf, path string) error {
	return k.Load(file.Provider(path), yaml.Parser())
}

func loadDir(path string, k *koanf.Koanf) error {
	err := filepath.WalkDir(path, func(filePath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if path == filePath {
			return nil
		}

		// Ignore non YAML files
		if !strings.HasSuffix(filePath, ".yml") && !strings.HasSuffix(filePath, ".yaml") {
			return nil
		}

		isRegular, err := isRegularFile(filePath)
		if err != nil {
			return err
		}

		// Ignore non regular files (directories, sockets, etc.)
		if !isRegular {
			return nil
		}

		if err := loadFile(k, filePath); err != nil {
			return err
		}

		return nil
	})

	return err
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
		data interface{},
	) (interface{}, error) {
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
