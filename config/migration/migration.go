// Package migration helps with migrating deprecated config options.
//
// `panic` is only used for programmer errors, meaning they will only trigger during development.
package migration

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/creasty/defaults"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

// Migrate checks each field of `deprecated` to see if a migration can and should be run.
//
// Each field must be a pointer: this allows knowing if the user has set a value in the config.
func Migrate(logger *logrus.Entry, optPrefix string, deprecated any, newOptions map[string]Migrator) bool {
	deprecatedVal := reflect.ValueOf(deprecated)
	deprecatedTyp := deprecatedVal.Type()

	usesDepredOpts := false

	for i := 0; i < deprecatedTyp.NumField(); i++ {
		field := deprecatedTyp.Field(i)
		fieldTag := field.Tag.Get("yaml")
		oldName := fullname(optPrefix, fieldTag)

		migrator, ok := newOptions[fieldTag]
		if !ok {
			panic(fmt.Errorf("deprecated option %s has no matching %T", oldName, migrator))
		}

		delete(newOptions, fieldTag) // so we know it's been checked

		migrator.dest.prefix = optPrefix

		val := deprecatedVal.Field(i)
		if val.Type().Kind() != reflect.Pointer {
			panic(fmt.Errorf("deprecated option %s must be a pointer", oldName))
		}

		if field.Tag.Get("default") != "" {
			panic(fmt.Errorf("deprecated option %s must not have a default", oldName))
		}

		if val.IsNil() {
			// Deprecated option is not defined in the user's config
			continue
		}

		usesDepredOpts = true
		val = val.Elem() // deref the pointer

		if !migrator.dest.IsDefault() {
			logger.
				WithFields(logrus.Fields{
					migrator.dest.Name(): migrator.dest.Value.Interface(),
					oldName:              val.Interface(),
				}).
				Errorf(
					"config options %q (new) and %q (deprecated) are both set, ignoring the deprecated one",
					migrator.dest, oldName,
				)

			continue
		}

		logger.Warnf("config option %q is deprecated, please use %q instead", oldName, migrator.dest)

		migrator.apply(oldName, val)
	}

	if len(newOptions) != 0 {
		panic(fmt.Errorf("%q has unused migrations: %v", optPrefix, maps.Keys(newOptions)))
	}

	return usesDepredOpts
}

type applyFunc func(oldName string, oldValue reflect.Value)

type Migrator struct {
	dest  *Dest
	apply applyFunc
}

func newMigrator(dest *Dest, apply applyFunc) Migrator {
	return Migrator{dest, apply}
}

// Move copies the deprecated option's value to `dest`.
func Move(dest *Dest) Migrator {
	return newMigrator(dest, func(oldName string, oldValue reflect.Value) {
		dest.Value.Set(oldValue)
	})
}

// Apply calls `apply` with the deprecated value casted to `T`.
func Apply[T any](dest *Dest, apply func(oldValue T)) Migrator {
	return newMigrator(dest, func(oldName string, oldValue reflect.Value) {
		valItf := oldValue.Interface()
		valTyped, ok := valItf.(T)
		if !ok {
			panic(fmt.Errorf("%q migration types don't match: cannot convert %v to %T", oldName, valItf, valTyped))
		}

		apply(valTyped)
	})
}

type Dest struct {
	prefix string
	name   string

	Value   reflect.Value
	Default any
}

// To creates a new `Dest` from an option name (relative to the `Migrate` prefix) and the struct containing that option.
func To[T any](newName string, newContainerStruct *T) *Dest {
	stVal := reflect.ValueOf(newContainerStruct).Elem()

	if stVal.Type().Kind() == reflect.Pointer {
		panic(fmt.Errorf("newContainerStruct for %s is a double pointer: %T", newName, newContainerStruct))
	}

	// Find the field matching `newName` in `newContainerStruct`
	fieldIdx, newVal := func() (int, reflect.Value) {
		parts := strings.Split(newName, ".")
		tag := parts[len(parts)-1]

		for i := 0; i < stVal.NumField(); i++ {
			field := stVal.Type().Field(i)
			if field.Tag.Get("yaml") == tag {
				return i, stVal.Field(i)
			}
		}

		panic(fmt.Errorf("migrated option %q not found in %T", newName, *newContainerStruct))
	}()

	// Get the default value of the new option
	newDefaultVal := func() reflect.Value {
		defaultVals := new(T)
		defaults.MustSet(defaultVals)

		return reflect.ValueOf(defaultVals).Elem().Field(fieldIdx)
	}()

	return &Dest{
		prefix:  "", // set by Run
		name:    newName,
		Value:   newVal,
		Default: newDefaultVal.Interface(),
	}
}

func (d *Dest) Name() string {
	return fullname(d.prefix, d.name)
}

func (d *Dest) IsDefault() bool {
	return reflect.DeepEqual(d.Value.Interface(), d.Default)
}

func (d *Dest) String() string {
	return d.Name()
}

func fullname(prefix, name string) string {
	if len(prefix) == 0 {
		return name
	}

	return fmt.Sprintf("%s.%s", prefix, name)
}
