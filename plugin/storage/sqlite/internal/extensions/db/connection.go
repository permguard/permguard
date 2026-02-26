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
	"errors"
	"flag"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // SQLite driver

	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	flagPrefixEndingSQLite = "storage-engine.sqlite"
	flagSuffixDBName       = "dbname"
)

// SQLiteConnectionConfig holds the configuration for the connection.
type SQLiteConnectionConfig struct {
	storageKind storage.Kind
	dbName      string
}

// NewSQLiteConnectionConfig creates a new connection factory configuration.
func NewSQLiteConnectionConfig() (*SQLiteConnectionConfig, error) {
	return &SQLiteConnectionConfig{
		storageKind: storage.StorageSQLite,
	}, nil
}

// AddFlags adds flags.
func (c *SQLiteConnectionConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.String(options.FlagName(flagPrefixEndingSQLite, flagSuffixDBName), "permguard", "sqlite database name")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *SQLiteConnectionConfig) InitFromViper(v *viper.Viper) error {
	c.dbName = strings.ToLower(v.GetString(options.FlagName(flagPrefixEndingSQLite, flagSuffixDBName)))
	return nil
}

// Storage returns the storage kind.
func (c *SQLiteConnectionConfig) Storage() storage.Kind {
	return c.storageKind
}

// DBName returns the database name.
func (c *SQLiteConnectionConfig) DBName() string {
	return c.dbName
}

// SQLiteConnector is the interface for the sqlite connector.
type SQLiteConnector interface {
	// Storage returns the storage kind.
	Storage() storage.Kind
	// Connect connects to sqlite and return a client.
	Connect(logger *zap.Logger, ctx *storage.Context) (*sqlx.DB, error)
	// Disconnect disconnects from sqlite.
	Disconnect(logger *zap.Logger, ctx *storage.Context) error
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
		return nil, errors.New("storage: sqlite connection configuration cannot be nil")
	}
	return &SQLiteConnection{
		config: connectionCgf,
	}, nil
}

// Storage returns the storage kind.
func (c *SQLiteConnection) Storage() storage.Kind {
	return c.config.Storage()
}

// Connect connects to sqlite and return a client.
func (c *SQLiteConnection) Connect(_ *zap.Logger, ctx *storage.Context) (*sqlx.DB, error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	if c.db != nil {
		return c.db, nil
	}
	hostCfgReader, err := ctx.HostConfigReader()
	if err != nil {
		return nil, errors.Join(errors.New("storage: cannot get host config reader"), err)
	}
	filePath := hostCfgReader.AppData()
	dbName := c.config.DBName()
	if !strings.HasSuffix(dbName, ".db") {
		dbName += ".db"
	}
	dbPath := filepath.Join(filePath, dbName)
	db, err := sqlx.Connect("sqlite", dbPath)
	if err != nil {
		return nil, errors.Join(errors.New("storage: cannot connect to sqlite"), err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, errors.Join(errors.New("storage: cannot enable foreign keys on sqlite"), err)
	}
	c.db = db
	return c.db, nil
}

// Disconnect disconnects from sqlite.
func (c *SQLiteConnection) Disconnect(_ *zap.Logger, _ *storage.Context) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	if c.db == nil {
		return nil
	}
	err := c.db.Close()
	if err != nil {
		return errors.Join(errors.New("storage: cannot disconnect from sqlite"), err)
	}
	c.db = nil
	return nil
}
