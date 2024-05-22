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

package postgres

import (
	"errors"
	"flag"

	"github.com/spf13/viper"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// PostgresStorageFactoryConfig holds the configuration for the server factory.
type PostgresStorageFactoryConfig struct {
	config *PostgresConnectionConfig
}

// NewPostgresStorageFactoryConfig creates a new server factory configuration.
func NewPostgresStorageFactoryConfig() (*PostgresStorageFactoryConfig, error) {
	dbConnCfg, err := newPostgresConnectionConfig()
	if err != nil {
		return nil, err
	}
	return &PostgresStorageFactoryConfig{
		config: dbConnCfg,
	}, nil
}

// AddFlags adds flags.
func (c *PostgresStorageFactoryConfig) AddFlags(flagSet *flag.FlagSet) error {
	return c.config.AddFlags(flagSet)
}

// InitFromViper initializes the configuration from viper.
func (c *PostgresStorageFactoryConfig) InitFromViper(v *viper.Viper) error {
	err := c.config.InitFromViper(v)
	return err
}

// PostgresStorageFactory holds the configuration for the server factory.
type PostgresStorageFactory struct {
	config     *PostgresStorageFactoryConfig
	connection PostgresConnector
}

// NewPostgresStorageFactory creates a new server factory configuration.
func NewPostgresStorageFactory(storageFctyCfg *PostgresStorageFactoryConfig) (*PostgresStorageFactory, error) {
	connection, err := newPostgresConnection(storageFctyCfg.config)
	if err != nil {
		return nil, err
	}
	return &PostgresStorageFactory{
		config:     storageFctyCfg,
		connection: connection,
	}, nil
}

// CreateCentralStorage returns the central storage.
func (f *PostgresStorageFactory) CreateCentralStorage(storageContext *azstorage.StorageContext) (azstorage.CentralStorage, error) {
	return newPostgresCentralStorage(storageContext, f.connection)
}

// CreateProximityStorage returns the proximity storage.
func (f *PostgresStorageFactory) CreateProximityStorage(storageContext *azstorage.StorageContext) (azstorage.ProximityStorage, error) {
	return nil, errors.New("posgres: proximity storage not implemented")
}
