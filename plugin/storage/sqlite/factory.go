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

package sqlite

import (
	"errors"
	"flag"

	"github.com/spf13/viper"

	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage"
	"github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
)

// SQLiteStorageFactoryConfig holds the configuration for the server factory.
type SQLiteStorageFactoryConfig struct {
	config *db.SQLiteConnectionConfig
}

// NewSQLiteStorageFactoryConfig creates a new server factory configuration.
func NewSQLiteStorageFactoryConfig() (*SQLiteStorageFactoryConfig, error) {
	dbConnCfg, err := db.NewSQLiteConnectionConfig()
	if err != nil {
		return nil, err
	}
	return &SQLiteStorageFactoryConfig{
		config: dbConnCfg,
	}, nil
}

// AddFlags adds flags.
func (c *SQLiteStorageFactoryConfig) AddFlags(flagSet *flag.FlagSet) error {
	return c.config.AddFlags(flagSet)
}

// InitFromViper initializes the configuration from viper.
func (c *SQLiteStorageFactoryConfig) InitFromViper(v *viper.Viper) error {
	err := c.config.InitFromViper(v)
	return err
}

// SQLiteStorageFactory holds the configuration for the server factory.
type SQLiteStorageFactory struct {
	config          *SQLiteStorageFactoryConfig
	sqliteConnector db.SQLiteConnector
}

// NewSQLiteStorageFactory creates a new server factory configuration.
func NewSQLiteStorageFactory(storageFctyCfg *SQLiteStorageFactoryConfig) (*SQLiteStorageFactory, error) {
	if storageFctyCfg == nil {
		return nil, errors.New("storage: storage factory configuration cannot be nil")
	}
	connection, err := db.NewSQLiteConnection(storageFctyCfg.config)
	if err != nil {
		return nil, err
	}
	return &SQLiteStorageFactory{
		config:          storageFctyCfg,
		sqliteConnector: connection,
	}, nil
}

// CreateCentralStorage returns the central storage.
func (f *SQLiteStorageFactory) CreateCentralStorage(storageContext *storage.StorageContext) (storage.CentralStorage, error) {
	return centralstorage.NewSQLiteCentralStorage(storageContext, f.sqliteConnector)
}
