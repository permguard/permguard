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

package zap

import (
	"flag"

	"github.com/spf13/viper"

	"github.com/permguard/permguard/pkg/agents/services"
)

// ZAPServiceFactoryConfig holds the configuration for the server factory.
type ZAPServiceFactoryConfig struct {
	config *ZAPServiceConfig
}

// NewZAPServiceFactoryConfig creates a new server factory configuration.
func NewZAPServiceFactoryConfig() (*ZAPServiceFactoryConfig, error) {
	zapServiceConfig, err := NewZAPServiceConfig()
	if err != nil {
		return nil, err
	}
	return &ZAPServiceFactoryConfig{
		config: zapServiceConfig,
	}, nil
}

// AddFlags adds flags.
func (c *ZAPServiceFactoryConfig) AddFlags(flagSet *flag.FlagSet) error {
	return c.config.AddFlags(flagSet)
}

// InitFromViper initializes the configuration from viper.
func (c *ZAPServiceFactoryConfig) InitFromViper(v *viper.Viper) error {
	err := c.config.InitFromViper(v)
	return err
}

// ZAPServiceFactory holds the configuration for the server factory.
type ZAPServiceFactory struct {
	config *ZAPServiceFactoryConfig
}

// NewZAPServiceFactory creates a new server factory configuration.
func NewZAPServiceFactory(serviceFctyCfg *ZAPServiceFactoryConfig) (*ZAPServiceFactory, error) {
	return &ZAPServiceFactory{
		config: serviceFctyCfg,
	}, nil
}

// Create creates a new service.
func (f *ZAPServiceFactory) Create() (services.Serviceable, error) {
	service, err := NewZAPService(f.config.config)
	return service, err
}
