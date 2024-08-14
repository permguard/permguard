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

package db

import (
	"context"
	"flag"
	"strings"

	"github.com/spf13/viper"
	"gorm.io/gorm"

	"go.uber.org/zap"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	flagPrefixEndingSQLite = "stroage.engine.sqlite"
	flagSuffixPath         = "path"
)

// SQLiteConnectionConfig holds the configuration for the connection.
type SQLiteConnectionConfig struct {
	storageKind azstorage.StorageKind
	path        string
}

// NewSQLiteConnectionConfig creates a new connection factory configuration.
func NewSQLiteConnectionConfig() (*SQLiteConnectionConfig, error) {
	return &SQLiteConnectionConfig{
		storageKind: azstorage.StorageSQLite,
	}, nil
}

// AddFlags adds flags.
func (c *SQLiteConnectionConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.String(azconfigs.FlagName(flagPrefixEndingSQLite, flagSuffixPath), "localhost", "sqlite path")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *SQLiteConnectionConfig) InitFromViper(v *viper.Viper) error {
	c.path = strings.ToLower(v.GetString(azconfigs.FlagName(flagPrefixEndingSQLite, flagSuffixPath)))
	return nil
}

// GetStorage returns the storage kind.
func (c *SQLiteConnectionConfig) GetStorage() azstorage.StorageKind {
	return c.storageKind
}

// GetPath returns the path.
func (c *SQLiteConnectionConfig) GetPath() string {
	return c.path
}

// SQLiteConnector is the interface for the sqlite connector.
type SQLiteConnector interface {
	// GetStorage returns the storage kind.
	GetStorage() azstorage.StorageKind
	// Connect connects to sqlite and return a client.
	Connect(logger *zap.Logger, ctx context.Context) (*gorm.DB, error)
	// Disconnect disconnects from sqlite.
	Disconnect(logger *zap.Logger, ctx context.Context) error
}

// SQLiteConnection holds the connection's configuration.
type SQLiteConnection struct {
	config *SQLiteConnectionConfig
}

// NewSQLiteConnection creates a connection.
func NewSQLiteConnection(connectionCgf *SQLiteConnectionConfig) (SQLiteConnector, error) {
	return &SQLiteConnection{
		config: connectionCgf,
	}, nil
}

// GetStorage returns the storage kind.
func (c *SQLiteConnection) GetStorage() azstorage.StorageKind {
	return c.config.GetStorage()
}

// Connect connects to sqlite and return a client.
func (c *SQLiteConnection) Connect(logger *zap.Logger, ctx context.Context) (*gorm.DB, error) {
	return nil, nil
}

// Disconnect disconnects from sqlite.
func (c *SQLiteConnection) Disconnect(logger *zap.Logger, ctx context.Context) error {
	return nil
}
