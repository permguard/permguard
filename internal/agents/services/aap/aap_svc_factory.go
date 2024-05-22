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

package aap

import (
	"flag"

	"github.com/spf13/viper"

	azservices "github.com/permguard/permguard/pkg/agents/services"
)

// AAPServiceFactoryConfig holds the configuration for the server factory.
type AAPServiceFactoryConfig struct {
	config *AAPServiceConfig
}

// NewAAPServiceFactoryConfig creates a new server factory configuration.
func NewAAPServiceFactoryConfig() (*AAPServiceFactoryConfig, error) {
	aAPServiceConfig, err := NewAAPServiceConfig()
	if err != nil {
		return nil, err
	}
	return &AAPServiceFactoryConfig{
		config: aAPServiceConfig,
	}, nil
}

// AddFlags adds flags.
func (c *AAPServiceFactoryConfig) AddFlags(flagSet *flag.FlagSet) error {
	return c.config.AddFlags(flagSet)
}

// InitFromViper initializes the configuration from viper.
func (c *AAPServiceFactoryConfig) InitFromViper(v *viper.Viper) error {
	err := c.config.InitFromViper(v)
	return err
}

// AAPServiceFactory holds the configuration for the server factory.
type AAPServiceFactory struct {
	config *AAPServiceFactoryConfig
}

// NewAAPServiceFactory creates a new server factory configuration.
func NewAAPServiceFactory(serviceFctyCfg *AAPServiceFactoryConfig) (*AAPServiceFactory, error) {
	return &AAPServiceFactory{
		config: serviceFctyCfg,
	}, nil
}

// Create creates a new service.
func (f *AAPServiceFactory) Create() (azservices.Serviceable, error) {
	service, err := NewAAPService(f.config.config)
	return service, err
}
