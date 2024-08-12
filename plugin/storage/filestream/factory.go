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

	"github.com/spf13/viper"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azifsvolumes "github.com/permguard/permguard/plugin/storage/filestream/internal/volumes"
	azifscntrlstorage "github.com/permguard/permguard/plugin/storage/filestream/internal/centralstorage"
)

// FileStreamStorageFactoryConfig holds the configuration for the server factory.
type FileStreamStorageFactoryConfig struct {
	config *azifsvolumes.FileStreamVolumeConfig
}

// NewFileStreamStorageFactoryConfig creates a new server factory configuration.
func NewFileStreamStorageFactoryConfig() (*FileStreamStorageFactoryConfig, error) {
	dbConnCfg, err := azifsvolumes.NewFileStreamVolumeConfig()
	if err != nil {
		return nil, err
	}
	return &FileStreamStorageFactoryConfig{
		config: dbConnCfg,
	}, nil
}

// AddFlags adds flags.
func (c *FileStreamStorageFactoryConfig) AddFlags(flagSet *flag.FlagSet) error {
	return c.config.AddFlags(flagSet)
}

// InitFromViper initializes the configuration from viper.
func (c *FileStreamStorageFactoryConfig) InitFromViper(v *viper.Viper) error {
	err := c.config.InitFromViper(v)
	return err
}

// FileStreamStorageFactory holds the configuration for the server factory.
type FileStreamStorageFactory struct {
	config       *FileStreamStorageFactoryConfig
	volumeBinder azifsvolumes.FileStreamVolumeBinder
}

// NewFileStreamStorageFactory creates a new server factory configuration.
func NewFileStreamStorageFactory(storageFctyCfg *FileStreamStorageFactoryConfig) (*FileStreamStorageFactory, error) {
	volume, err := azifsvolumes.NewFileStreamVolume(storageFctyCfg.config)
	if err != nil {
		return nil, err
	}
	return &FileStreamStorageFactory{
		config:       storageFctyCfg,
		volumeBinder: volume,
	}, nil
}

// CreateCentralStorage returns the central storage.
func (f *FileStreamStorageFactory) CreateCentralStorage(storageContext *azstorage.StorageContext) (azstorage.CentralStorage, error) {
	return azifscntrlstorage.NewFileStreamCentralStorage(storageContext, f.volumeBinder)
}

// CreateProximityStorage returns the proximity storage.
func (f *FileStreamStorageFactory) CreateProximityStorage(storageContext *azstorage.StorageContext) (azstorage.ProximityStorage, error) {
	return nil, azerrors.WrapSystemError(azerrors.ErrNotImplemented, "storage: proximity storage not implemented by the filestream plugin.")
}
