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
	"flag"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azconfigs "github.com/permguard/permguard/pkg/configs"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

const (
	flagPrefixEndingSQLite = "stroage.engine.sqlite"
	flagSuffixDBName       = "dbname"
)

// SQLiteConnectionConfig holds the configuration for the connection.
type SQLiteConnectionConfig struct {
	storageKind azstorage.StorageKind
	dbName      string
}

// NewSQLiteConnectionConfig creates a new connection factory configuration.
func NewSQLiteConnectionConfig() (*SQLiteConnectionConfig, error) {
	return &SQLiteConnectionConfig{
		storageKind: azstorage.StorageSQLite,
	}, nil
}

// AddFlags adds flags.
func (c *SQLiteConnectionConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.String(azconfigs.FlagName(flagPrefixEndingSQLite, flagSuffixDBName), "permguard", "sqlite database name")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *SQLiteConnectionConfig) InitFromViper(v *viper.Viper) error {
	c.dbName = strings.ToLower(v.GetString(azconfigs.FlagName(flagPrefixEndingSQLite, flagSuffixDBName)))
	return nil
}

// GetStorage returns the storage kind.
func (c *SQLiteConnectionConfig) GetStorage() azstorage.StorageKind {
	return c.storageKind
}

// GetDBName returns the database name.
func (c *SQLiteConnectionConfig) GetDBName() string {
	return c.dbName
}

// SQLiteConnector is the interface for the sqlite connector.
type SQLiteConnector interface {
	// GetStorage returns the storage kind.
	GetStorage() azstorage.StorageKind
	// Connect connects to sqlite and return a client.
	Connect(logger *zap.Logger, ctx *azstorage.StorageContext) (*sqlx.DB, error)
	// Disconnect disconnects from sqlite.
	Disconnect(logger *zap.Logger, ctx *azstorage.StorageContext) error
}

// SQLiteConnection holds the connection's configuration.
type SQLiteConnection struct {
	config   *SQLiteConnectionConfig
	connLock sync.Mutex
	db       *sqlx.DB
}

// NewSQLiteConnection creates a connection.
func NewSQLiteConnection(connectionCgf *SQLiteConnectionConfig) (SQLiteConnector, error) {
	if connectionCgf == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrConfigurationGeneric, "storage: sqlite connection configuration cannot be nil.")
	}
	return &SQLiteConnection{
		config: connectionCgf,
	}, nil
}

// GetStorage returns the storage kind.
func (c *SQLiteConnection) GetStorage() azstorage.StorageKind {
	return c.config.GetStorage()
}

// Connect connects to sqlite and return a client.
func (c *SQLiteConnection) Connect(logger *zap.Logger, ctx *azstorage.StorageContext) (*sqlx.DB, error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	if c.db != nil {
		return c.db, nil
	}
	filePath := ctx.GetAppData()
	dbName := c.config.GetDBName()
	if !strings.HasSuffix(dbName, ".db") {
		dbName += ".db"
	}
	dbPath := filepath.Join(filePath, dbName)
	db, err := sqlx.Connect("sqlite3", dbPath)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrStorageGeneric, "storage: cannot connect to sqlite")
	}
	db.Exec("PRAGMA foreign_keys = ON;")
	c.db = db
	return c.db, nil
}

// Disconnect disconnects from sqlite.
func (c *SQLiteConnection) Disconnect(logger *zap.Logger, ctx *azstorage.StorageContext) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	if c.db == nil {
		return nil
	}
	err := c.db.Close()
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrStorageGeneric, "storage: cannot disconnect from sqlite")
	}
	c.db = nil
	return nil
}
