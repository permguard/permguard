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

package storage

import (
	"flag"
	"strings"

	"github.com/spf13/viper"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	flagPrefixEndingFileStream = "stroage.engine.filestream"
	flagSuffixPath             = "path"
)

var flagValDefPosgresSSLModes = []string{"disable", "require", "verify-ca", "verify-full"}

// FileStreamPersistenceConfig holds the configuration for the server.
type FileStreamPersistenceConfig struct {
	storageKind azstorage.StorageKind
	path        string
}

// NewFileStreamPersistenceConfig creates a new server factory configuration.
func NewFileStreamPersistenceConfig() (*FileStreamPersistenceConfig, error) {
	return &FileStreamPersistenceConfig{
		storageKind: azstorage.StorageFileStream,
	}, nil
}

// AddFlags adds flags.
func (c *FileStreamPersistenceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.String(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixPath), "localhost", "filestream path")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *FileStreamPersistenceConfig) InitFromViper(v *viper.Viper) error {
	c.path = strings.ToLower(v.GetString(azconfigs.FlagName(flagPrefixEndingFileStream, flagSuffixPath)))
	return nil
}

// GetStorage returns the storage kind.
func (c *FileStreamPersistenceConfig) GetStorage() azstorage.StorageKind {
	return c.storageKind
}

// GetPath returns the path.
func (c *FileStreamPersistenceConfig) GetPath() string {
	return c.path
}

// FileStreamConnector is the interface for the filestream persistence.
type FileStreamConnector interface {
	// GetStorage returns the storage kind.
	GetStorage() azstorage.StorageKind
}

// FileStreamPersistence holds the configuration for the server.
type FileStreamPersistence struct {
	config     *FileStreamPersistenceConfig
}

// NewFileStreamPersistence creates a new server configuration.
func NewFileStreamPersistence(persistenceCgf *FileStreamPersistenceConfig) (FileStreamConnector, error) {
	return &FileStreamPersistence{
		config: persistenceCgf,
	}, nil
}

// GetStorage returns the storage kind.
func (c *FileStreamPersistence) GetStorage() azstorage.StorageKind {
	return c.config.GetStorage()
}
