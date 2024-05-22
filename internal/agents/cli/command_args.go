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

package cli

import (
	"strings"

	"github.com/spf13/viper"
)

// stringFromArgs returns the value of the argument from the command line or the default value.
func stringFromArgs(argPrefix string, argName string, argDefault string, args []string, v *viper.Viper) string {
	flagName := argPrefix + argName
	value := ""
	for i, argument := range args {
		if i == 0 {
			continue
		}
		if !strings.HasPrefix(argument, flagName) {
			continue
		}
		if argument == flagName && i < len(args)-1 {
			value = args[i+1]
		} else if strings.HasPrefix(argument, flagName+"=") {
			value = argument[(len(flagName) + 1):]
		}
		if value == "" || strings.HasPrefix(value, "-") {
			value = ""
			continue
		}
		return value
	}
	if value == "" {
		value := v.GetString(argName)
		if value != "" {
			return value
		}
	}
	return argDefault
}
