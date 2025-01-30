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
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azfiles "github.com/permguard/permguard-core/pkg/extensions/files"
)

// configureViper configures the viper.
func configureViper(v *viper.Viper) {
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.SetEnvPrefix("PERMGUARD")
}

// checkIfKeyExists checks if the key exists.
func checkIfKeyExists(v *viper.Viper, key string) bool {
	if !strings.Contains(key, ".") {
		return v.IsSet(key)
	}
	keys := strings.Split(key, ".")
	settings := v.AllSettings()
	current := settings
	for i := 0; i < len(keys); i++ {
		keyPart := keys[i]
		if _, ok := current[keyPart]; !ok {
			return false
		}
		if i < len(keys)-1 {
			nestedMap, ok := current[keyPart].(map[string]interface{})
			if !ok {
				return false
			}
			current = nestedMap
		}
	}
	return true
}

// NewViper creates a new viper.
func NewViper() (*viper.Viper, error) {
	v := viper.New()
	configureViper(v)
	return v, nil
}

// NewViperFromConfig creates a new viper from the config.
func NewViperFromConfig(onCreation func(*viper.Viper) map[string]any) (*viper.Viper, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(homeDir, ".permguard")
	configName := "config"
	config := filepath.Join(configPath, configName+".toml")
	_, err = azfiles.CreateFileIfNotExists(config)
	if err != nil {
		return nil, err
	}
	v := viper.New()
	v.AddConfigPath(configPath)
	v.SetConfigName(configName)
	v.SetConfigType("toml")
	err = v.ReadInConfig()
	if err != nil {
		return nil, err
	}
	if onCreation != nil {
		mapValues := onCreation(v)
		for mapValuesKey, mapValuesValue := range mapValues {
			if checkIfKeyExists(v, mapValuesKey) {
				continue
			}
			v.Set(mapValuesKey, mapValuesValue)
		}
		v.WriteConfig()
	}
	configureViper(v)
	return v, nil
}

// ResetViperConfig resets the viper config.
func ResetViperConfig(v *viper.Viper) (string, error) {
	configFile := v.ConfigFileUsed()
	_, err := azfiles.DeletePath(configFile)
	return configFile, err
}

// OverrideViperFromConfig overrides the viper from the config.
func OverrideViperFromConfig(v *viper.Viper, valueMap map[string]interface{}) error {
	newViper, err := NewViperFromConfig(nil)
	if err != nil {
		return err
	}
	fileSettings := newViper.AllSettings()
	for key, value := range fileSettings {
		newViper.Set(key, value)
	}
	for key, value := range valueMap {
		newViper.Set(key, value)
	}
	return newViper.WriteConfigAs(v.ConfigFileUsed())
}

// Viperize creates a new viper and a new cobra command.
func Viperize(funcs ...func(*flag.FlagSet) error) (*viper.Viper, *cobra.Command, error) {
	viper := viper.New()
	cobra := &cobra.Command{}
	err := AddCobraFlags(cobra, viper, funcs...)
	return viper, cobra, err
}
