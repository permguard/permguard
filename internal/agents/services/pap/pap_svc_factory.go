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

package pap

import (
	"flag"

	"github.com/spf13/viper"

	azservices "github.com/permguard/permguard/pkg/agents/services"
)

// PAPServiceFactoryConfig holds the configuration for the server factory.
type PAPServiceFactoryConfig struct {
	config *PAPServiceConfig
}

// NewPAPServiceFactoryConfig creates a new server factory configuration.
func NewPAPServiceFactoryConfig() (*PAPServiceFactoryConfig, error) {
	papServiceConfig, err := NewPAPServiceConfig()
	if err != nil {
		return nil, err
	}
	return &PAPServiceFactoryConfig{
		config: papServiceConfig,
	}, nil
}

// AddFlags adds flags.
func (c *PAPServiceFactoryConfig) AddFlags(flagSet *flag.FlagSet) error {
	return c.config.AddFlags(flagSet)
}

// InitFromViper initializes the configuration from viper.
func (c *PAPServiceFactoryConfig) InitFromViper(v *viper.Viper) error {
	err := c.config.InitFromViper(v)
	return err
}

// PAPServiceFactory holds the configuration for the server factory.
type PAPServiceFactory struct {
	config *PAPServiceFactoryConfig
}

// NewPAPServiceFactory creates a new server factory configuration.
func NewPAPServiceFactory(papServiceCfg *PAPServiceFactoryConfig) (*PAPServiceFactory, error) {
	return &PAPServiceFactory{
		config: papServiceCfg,
	}, nil
}

// Create creates a new service.
func (f *PAPServiceFactory) Create() (azservices.Serviceable, error) {
	service, err := NewPAPService(f.config.config)
	return service, err
}
