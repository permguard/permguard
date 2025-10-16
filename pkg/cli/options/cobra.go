// Copyright 2024 Nitro Agility S.r.l.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"flag"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// FlagName returns the flag name.
func FlagName(flags ...string) string {
	sanitizedFlags := make([]string, len(flags))
	for i, flag := range flags {
		sanitizedFlags[i] = strings.ReplaceAll(flag, ".", "-", )
	}
	return strings.Join(sanitizedFlags, "-")
}

// AddFlag adds a flag to the viper.
func AddFlag[T any](v *viper.Viper, name string, value T, usage string) error {
	switch reflect.TypeOf(value) {
	case reflect.TypeOf(string("")):
		pflag.String(name, any(value).(string), usage)
	case reflect.TypeOf(bool(true)):
		pflag.Bool(name, any(value).(bool), usage)
	case reflect.TypeOf(int(0)):
		pflag.Int(name, any(value).(int), usage)
	default:
		panic("bootstrap: unsupported flag type")
	}
	err := v.BindPFlag(name, pflag.Lookup(name))
	return err
}

// AddCobraFlags adds flags to the viper and the cobra command.
func addCobraFlags(cmd *cobra.Command, v *viper.Viper, isPersistent bool, funcs ...func(*flag.FlagSet) error) error {
	flagSet := new(flag.FlagSet)
	for _, f := range funcs {
		err := f(flagSet)
		if err != nil {
			return err
		}
	}
	var cmdFlagSet *pflag.FlagSet
	if isPersistent {
		cmdFlagSet = cmd.PersistentFlags()
	} else {
		cmdFlagSet = cmd.Flags()
	}
	cmdFlagSet.AddGoFlagSet(flagSet)
	err := v.BindPFlags(cmdFlagSet)
	if err != nil {
		return err
	}
	return nil
}

// AddCobraFlags adds flags to the viper and the cobra command.
func AddCobraFlags(cmd *cobra.Command, v *viper.Viper, funcs ...func(*flag.FlagSet) error) error {
	return addCobraFlags(cmd, v, false, funcs...)
}

func AddCobraPersistentFlags(cmd *cobra.Command, v *viper.Viper, funcs ...func(*flag.FlagSet) error) error {
	return addCobraFlags(cmd, v, true, funcs...)
}
