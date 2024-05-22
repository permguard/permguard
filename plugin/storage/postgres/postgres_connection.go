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
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/viper"
	"golang.org/x/exp/slices"

	"go.uber.org/zap"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"moul.io/zapgorm2"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	flagPrefixEndingPostgres = "stroage.engine.postgres"
	flagSuffixHost           = "host"
	flagSuffixPort           = "port"
	flagSuffixSSLMode        = "sslmode"
	flagSuffixAuthUsername   = "auth.username"
	flagSuffixAuthPassword   = "auth.password"
	flagSuffixDatabase       = "database"
)

var flagValDefPosgresSSLModes = []string{"disable", "require", "verify-ca", "verify-full"}

// PostgresConnectionConfig holds the configuration for the server.
type PostgresConnectionConfig struct {
	storageKind azstorage.StorageKind
	host        string
	port        int
	sslmode     string
	username    string
	password    string
	database    string
}

// newPostgresConnectionConfig creates a new server factory configuration.
func newPostgresConnectionConfig() (*PostgresConnectionConfig, error) {
	return &PostgresConnectionConfig{
		storageKind: azstorage.StoragePostgres,
	}, nil
}

// AddFlags adds flags.
func (c *PostgresConnectionConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.String(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixHost), "localhost", "postgres host")
	flagSet.Int(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixPort), 5432, "postgres port")
	flagSet.String(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixSSLMode), "disable", "postgres ssl mode")
	flagSet.String(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixAuthUsername), "admin", "postgres username")
	flagSet.String(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixAuthPassword), "admin", "postgres password")
	flagSet.String(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixDatabase), "permguard", "postgres database")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *PostgresConnectionConfig) InitFromViper(v *viper.Viper) error {
	c.host = strings.ToLower(v.GetString(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixHost)))
	c.port = v.GetInt(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixPort))
	c.sslmode = strings.ToLower(v.GetString(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixSSLMode)))
	if !slices.Contains(flagValDefPosgresSSLModes, c.sslmode) {
		return fmt.Errorf("invalid sslmode %s", c.sslmode)
	}
	c.username = v.GetString(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixAuthUsername))
	c.password = v.GetString(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixAuthPassword))
	c.database = strings.ToLower(v.GetString(azconfigs.FlagName(flagPrefixEndingPostgres, flagSuffixDatabase)))
	return nil
}

// GetStorage returns the storage kind.
func (c *PostgresConnectionConfig) GetStorage() azstorage.StorageKind {
	return c.storageKind
}

// GetHost returns the host.
func (c *PostgresConnectionConfig) GetHost() string {
	return c.host
}

// GetPort returns the port.
func (c *PostgresConnectionConfig) GetPort() int {
	return c.port
}

// GetSSLMode returns the ssl mode.
func (c *PostgresConnectionConfig) GetSSLMode() string {
	return c.sslmode
}

// GetUsername returns the username.
func (c *PostgresConnectionConfig) GetUsername() string {
	return c.username
}

// GetPassword returns the password.
func (c *PostgresConnectionConfig) GetPassword() string {
	return c.password
}

// GetDatabase returns the database.
func (c *PostgresConnectionConfig) GetDatabase() string {
	return c.database
}

// GetConnectionString returns the connection string.
func (c *PostgresConnectionConfig) GetConnectionString() (string, error) {
	host := c.host
	port := c.port
	username := c.username
	password := c.password
	dbname := c.database
	sslmode := c.sslmode
	connectionString := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s", host, port, username, password, dbname, sslmode)
	return connectionString, nil
}

// PostgresConnector is the interface for the postgres connection.
type PostgresConnector interface {
	// GetStorage returns the storage kind.
	GetStorage() azstorage.StorageKind
	// Connect connects to postgres and return a client.
	Connect(logger *zap.Logger, ctx context.Context) (*gorm.DB, error)
	// Disconnect disconnects from postgres.
	Disconnect(logger *zap.Logger, ctx context.Context) error
}

// PostgresConnection holds the configuration for the server.
type PostgresConnection struct {
	config   *PostgresConnectionConfig
	connLock sync.Mutex
	db       *gorm.DB
}

// newPostgresConnection creates a new server  configuration.
func newPostgresConnection(connectionCgf *PostgresConnectionConfig) (PostgresConnector, error) {
	return &PostgresConnection{
		config: connectionCgf,
	}, nil
}

// GetStorage returns the storage kind.
func (c *PostgresConnection) GetStorage() azstorage.StorageKind {
	return c.config.GetStorage()
}

// Connect connects to postgres and return a client.
func (c *PostgresConnection) Connect(logger *zap.Logger, ctx context.Context) (*gorm.DB, error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	if c.db != nil {
		return c.db, nil
	}
	connectionStr, err := c.config.GetConnectionString()
	if err != nil {
		logger.Error("storage: cannot connect to postgres", zap.Error(err))
		return nil, errors.New("storage: cannot connect to postgres")
	}
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  connectionStr,
		PreferSimpleProtocol: true, // disables implicit prepared statement usage. By default pgx automatically uses the extended protocol
	}), &gorm.Config{Logger: zapgorm2.New(logger)})
	if err != nil {
		return nil, errors.New("storage: cannot connect to postgres")
	}
	c.db = db
	return c.db, nil
}

// Disconnect disconnects from postgres.
func (c *PostgresConnection) Disconnect(logger *zap.Logger, ctx context.Context) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	if c.db == nil {
		return nil
	}
	sqlDB, err := c.db.DB()
	if err != nil {
		logger.Error("storage: cannot get underlying connection", zap.Error(err))
		return errors.New("storage: cannot disconnect from postgres")
	}
	err = sqlDB.Close()
	if err != nil {
		logger.Error("storage: cannot disconnect from postgres", zap.Error(err))
		return errors.New("storage: cannot disconnect from postgres")
	}
	return nil
}
