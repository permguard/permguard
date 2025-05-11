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

package servers

import (
	"flag"

	"github.com/spf13/viper"

	"github.com/permguard/permguard/pkg/agents/servers"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// ServerFactoryConfig holds the configuration for the server factory.
type ServerFactoryConfig struct {
	config               *ServerConfig
	centralStorageEngine storage.StorageKind
}

// NewServerFactoryConfig creates a new server factory configuration.
func NewServerFactoryConfig(initializer servers.ServerInitializer, centralStorageEngine storage.StorageKind) (*ServerFactoryConfig, error) {
	host := initializer.GetHost()
	storages := initializer.GetStorages(centralStorageEngine)
	storagesFactories, err := initializer.GetStoragesFactories(centralStorageEngine)
	if err != nil {
		return nil, err
	}
	services := initializer.GetServices()
	servicesFactories, err := initializer.GetServicesFactories()
	if err != nil {
		return nil, err
	}
	serverConfig, err := newServerConfig(host, centralStorageEngine, storages, storagesFactories, services, servicesFactories)
	if err != nil {
		return nil, err
	}
	return &ServerFactoryConfig{
		config:               serverConfig,
		centralStorageEngine: centralStorageEngine,
	}, nil
}

// AddFlags adds flags.
func (c *ServerFactoryConfig) AddFlags(flagSet *flag.FlagSet) error {
	return c.config.AddFlags(flagSet)
}

// InitFromViper initializes the configuration from viper.
func (c *ServerFactoryConfig) InitFromViper(v *viper.Viper) error {
	err := c.config.InitFromViper(v)
	return err
}
