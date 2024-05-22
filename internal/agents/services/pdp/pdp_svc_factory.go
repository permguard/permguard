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

	azservices "github.com/permguard/permguard/pkg/agents/services"
)

// PDPServiceFactoryConfig holds the configuration for the server factory.
type PDPServiceFactoryConfig struct {
	config *PDPServiceConfig
}

// NewPDPServiceFactoryConfig creates a new server factory configuration.
func NewPDPServiceFactoryConfig() (*PDPServiceFactoryConfig, error) {
	pDPServiceConfig, err := NewPDPServiceConfig()
	if err != nil {
		return nil, err
	}
	return &PDPServiceFactoryConfig{
		config: pDPServiceConfig,
	}, nil
}

// AddFlags adds flags.
func (c *PDPServiceFactoryConfig) AddFlags(flagSet *flag.FlagSet) error {
	return c.config.AddFlags(flagSet)
}

// InitFromViper initializes the configuration from viper.
func (c *PDPServiceFactoryConfig) InitFromViper(v *viper.Viper) error {
	err := c.config.InitFromViper(v)
	return err
}

// PDPServiceFactory holds the configuration for the server factory.
type PDPServiceFactory struct {
	config *PDPServiceFactoryConfig
}

// NewPDPServiceFactory creates a new server factory configuration.
func NewPDPServiceFactory(pdpServiceCfg *PDPServiceFactoryConfig) (*PDPServiceFactory, error) {
	return &PDPServiceFactory{
		config: pdpServiceCfg,
	}, nil
}

// Create creates a new service.
func (f *PDPServiceFactory) Create() (azservices.Serviceable, error) {
	service, err := NewPDPService(f.config.config)
	return service, err
}
