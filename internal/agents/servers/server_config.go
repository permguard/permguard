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
	"errors"
	"flag"

	"github.com/spf13/viper"

	"github.com/permguard/permguard/common/pkg/extensions/copier"
	"github.com/permguard/permguard/common/pkg/extensions/validators"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	flagPrefixServer  = "server"
	flagSuffixAppData = "appdata"
)

// ServerConfig holds the configuration for the server.
type ServerConfig struct {
	host                 services.HostKind
	debug                bool
	logLevel             string
	appData              string
	centralStorageEngine storage.StorageKind
	storages             []storage.StorageKind
	storagesFactories    map[storage.StorageKind]storage.StorageFactoryProvider
	services             []services.ServiceKind
	servicesFactories    map[services.ServiceKind]services.ServiceFactoryProvider
}

// newServerConfig creates a new server factory configuration.
func newServerConfig(host services.HostKind, centralStorageEngine storage.StorageKind,
	storages []storage.StorageKind, storagesFactories map[storage.StorageKind]storage.StorageFactoryProvider,
	services []services.ServiceKind, servicesFactories map[services.ServiceKind]services.ServiceFactoryProvider,
) (*ServerConfig, error) {
	return &ServerConfig{
		host:                 host,
		centralStorageEngine: centralStorageEngine,
		storages:             copier.CopySlice(storages),
		storagesFactories:    copier.CopyMap(storagesFactories),
		services:             copier.CopySlice(services),
		servicesFactories:    copier.CopyMap(servicesFactories),
	}, nil
}

// GetHost returns the host kind.
func (c *ServerConfig) GetHost() services.HostKind {
	return c.host
}

// GetCentralStorageEngine returns the central storage engine.
func (c *ServerConfig) GetCentralStorageEngine() storage.StorageKind {
	return c.centralStorageEngine
}

// GetStorages returns service kinds.
func (c *ServerConfig) GetStorages() []storage.StorageKind {
	return copier.CopySlice(c.storages)
}

// GetStoragesFactories returns factories.
func (c *ServerConfig) GetStoragesFactories() map[storage.StorageKind]storage.StorageFactoryProvider {
	return copier.CopyMap(c.storagesFactories)
}

// GetServices returns service kinds.
func (c *ServerConfig) GetServices() []services.ServiceKind {
	return copier.CopySlice(c.services)
}

// GetServicesFactories returns factories.
func (c *ServerConfig) GetServicesFactories() map[services.ServiceKind]services.ServiceFactoryProvider {
	return copier.CopyMap(c.servicesFactories)
}

// GetAppData returns the zone data.
func (c *ServerConfig) GetAppData() string {
	return c.appData
}

// AddFlags adds flags.
func (c *ServerConfig) AddFlags(flagSet *flag.FlagSet) error {
	err := options.AddFlagsForCommon(flagSet)
	if err != nil {
		return err
	}
	flagSet.String(options.FlagName(flagPrefixServer, flagSuffixAppData), "./", "directory to be used as zone data")
	for _, fcty := range c.storagesFactories {
		config, _ := fcty.GetFactoryConfig()
		err = config.AddFlags(flagSet)
		if err != nil {
			return err
		}
	}
	for _, fcty := range c.servicesFactories {
		config, _ := fcty.GetFactoryConfig()
		err = config.AddFlags(flagSet)
		if err != nil {
			return err
		}
	}
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *ServerConfig) InitFromViper(v *viper.Viper) error {
	debug, logLevel, err := options.InitFromViperForCommon(v)
	if err != nil {
		return err
	}
	c.debug = debug
	c.logLevel = logLevel
	c.appData = v.GetString(options.FlagName(flagPrefixServer, flagSuffixAppData))
	if !validators.IsValidPath(c.appData) {
		return errors.New("server: invalid app data directory")
	}
	for _, fcty := range c.storagesFactories {
		config, err := fcty.GetFactoryConfig()
		if err != nil {
			return err
		}
		err = config.InitFromViper(v)
		if err != nil {
			return err
		}
	}
	for _, fcty := range c.servicesFactories {
		config, err := fcty.GetFactoryConfig()
		if err != nil {
			return err
		}
		err = config.InitFromViper(v)
		if err != nil {
			return err
		}
	}
	return nil
}
