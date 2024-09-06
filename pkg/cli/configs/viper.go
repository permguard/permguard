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

package configs

import (
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azfiles "github.com/permguard/permguard/pkg/core/files"
)

// configureViper configures the viper.
func configureViper(v *viper.Viper) {
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.SetEnvPrefix("PERMGUARD")
}

// NewViper creates a new viper.
func NewViper() (*viper.Viper, error) {
	v := viper.New()
	configureViper(v)
	return v, nil
}

// NewViperFromConfig creates a new viper from the config.
func NewViperFromConfig(onCreation func(*viper.Viper) error) (*viper.Viper, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(homeDir, ".permguard")
	configName := "config"
	created, err := azfiles.CreateFileIfNotExists(configPath, configName)
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
	if created && onCreation != nil {
		return v, onCreation(v)
	}
	configureViper(v)
	return v, nil
}

// Viperize creates a new viper and a new cobra command.
func Viperize(funcs ...func(*flag.FlagSet) error) (*viper.Viper, *cobra.Command, error) {
	viper := viper.New()
	cobra := &cobra.Command{}
	err := AddCobraFlags(cobra, viper, funcs...)
	return viper, cobra, err
}
