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

package pdp

import (
	"flag"

	"github.com/spf13/viper"

	"github.com/permguard/permguard/pkg/agents/services"
)

// ServiceFactoryConfig holds the configuration for the server factory.
type ServiceFactoryConfig struct {
	config *ServiceConfig
}

// NewServiceFactoryConfig creates a new server factory configuration.
func NewServiceFactoryConfig() (*ServiceFactoryConfig, error) {
	pDPServiceConfig, err := NewServiceConfig()
	if err != nil {
		return nil, err
	}
	return &ServiceFactoryConfig{
		config: pDPServiceConfig,
	}, nil
}

// AddFlags adds flags.
func (c *ServiceFactoryConfig) AddFlags(flagSet *flag.FlagSet) error {
	return c.config.AddFlags(flagSet)
}

// InitFromViper initializes the configuration from viper.
func (c *ServiceFactoryConfig) InitFromViper(v *viper.Viper) error {
	err := c.config.InitFromViper(v)
	return err
}

// ServiceFactory holds the configuration for the server factory.
type ServiceFactory struct {
	config *ServiceFactoryConfig
}

// NewServiceFactory creates a new server factory configuration.
func NewServiceFactory(pdpServiceCfg *ServiceFactoryConfig) (*ServiceFactory, error) {
	return &ServiceFactory{
		config: pdpServiceCfg,
	}, nil
}

// Create creates a new service.
func (f *ServiceFactory) Create() (services.Serviceable, error) {
	service, err := NewService(f.config.config)
	return service, err
}
