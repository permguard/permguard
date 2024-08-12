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

package filestream

import (
	"flag"
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/viper"
	"golang.org/x/exp/slices"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	flagPrefixEndingFileStream = "stroage.engine.filestream"
	flagSuffixHost           = "host"
	flagSuffixPort           = "port"
	flagSuffixSSLMode        = "sslmode"
	flagSuffixAuthUsername   = "auth.username"
	flagSuffixAuthPassword   = "auth.password"
	flagSuffixDatabase       = "database"
)

var flagValDefPosgresSSLModes = []string{"disable", "require", "verify-ca", "verify-full"}

// FileStreamConnectionConfig holds the configuration for the server.
type FileStreamConnectionConfig struct {
	storageKind azstorage.StorageKind
	host        string
	port        int
	sslmode     string
	username    string
	password    string
	database    string
}

// newFileStreamConnectionConfig creates a new server factory configuration.
func newFileStreamConnectionConfig() (*FileStreamConnectionConfig, error) {
	return &FileStreamConnectionConfig{
		storageKind: azstorage.StorageFileStream,
	}, nil
}

// AddFlags adds flags.
func (c *FileStreamConnectionConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.String(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixHost), "localhost", "filestream host")
	flagSet.Int(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixPort), 5432, "filestream port")
	flagSet.String(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixSSLMode), "disable", "filestream ssl mode")
	flagSet.String(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixAuthUsername), "admin", "filestream username")
	flagSet.String(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixAuthPassword), "admin", "filestream password")
	flagSet.String(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixDatabase), "permguard", "filestream database")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *FileStreamConnectionConfig) InitFromViper(v *viper.Viper) error {
	c.host = strings.ToLower(v.GetString(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixHost)))
	c.port = v.GetInt(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixPort))
	c.sslmode = strings.ToLower(v.GetString(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixSSLMode)))
	if !slices.Contains(flagValDefPosgresSSLModes, c.sslmode) {
		return fmt.Errorf("invalid sslmode %s", c.sslmode)
	}
	c.username = v.GetString(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixAuthUsername))
	c.password = v.GetString(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixAuthPassword))
	c.database = strings.ToLower(v.GetString(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixDatabase)))
	return nil
}

// GetStorage returns the storage kind.
func (c *FileStreamConnectionConfig) GetStorage() azstorage.StorageKind {
	return c.storageKind
}

// GetHost returns the host.
func (c *FileStreamConnectionConfig) GetHost() string {
	return c.host
}

// GetPort returns the port.
func (c *FileStreamConnectionConfig) GetPort() int {
	return c.port
}

// GetSSLMode returns the ssl mode.
func (c *FileStreamConnectionConfig) GetSSLMode() string {
	return c.sslmode
}

// GetUsername returns the username.
func (c *FileStreamConnectionConfig) GetUsername() string {
	return c.username
}

// GetPassword returns the password.
func (c *FileStreamConnectionConfig) GetPassword() string {
	return c.password
}

// GetDatabase returns the database.
func (c *FileStreamConnectionConfig) GetDatabase() string {
	return c.database
}

// GetConnectionString returns the connection string.
func (c *FileStreamConnectionConfig) GetConnectionString() (string, error) {
	host := c.host
	port := c.port
	username := c.username
	password := c.password
	dbname := c.database
	sslmode := c.sslmode
	connectionString := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s", host, port, username, password, dbname, sslmode)
	return connectionString, nil
}

// FileStreamConnector is the interface for the filestream connection.
type FileStreamConnector interface {
	// GetStorage returns the storage kind.
	GetStorage() azstorage.StorageKind
}

// FileStreamConnection holds the configuration for the server.
type FileStreamConnection struct {
	config   *FileStreamConnectionConfig
	volumeLock sync.Mutex
}

// newFileStreamConnection creates a new server  configuration.
func newFileStreamConnection(connectionCgf *FileStreamConnectionConfig) (FileStreamConnector, error) {
	return &FileStreamConnection{
		config: connectionCgf,
	}, nil
}

// GetStorage returns the storage kind.
func (c *FileStreamConnection) GetStorage() azstorage.StorageKind {
	return c.config.GetStorage()
}
