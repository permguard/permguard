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

	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	azconfigs "github.com/permguard/permguard/pkg/configs"
	azifsvolumes "github.com/permguard/permguard/plugin/storage/filestream/internal/volumes"
)

const (
	flagUp   = "up"
	flagDown = "down"
)

// FileStreamStorageProvisioner is the storage provisioner for FileStream.
type FileStreamStorageProvisioner struct {
	debug    bool
	logLevel string
	logger   *zap.Logger
	up       bool
	down     bool
	config   *azifsvolumes.FileStreamVolumeConfig
}

// NewFileStreamStorageProvisioner creates a new FileStreamStorageProvisioner.
func NewFileStreamStorageProvisioner() (*FileStreamStorageProvisioner, error) {
	config, err := azifsvolumes.NewFileStreamVolumeConfig()
	if err != nil {
		return nil, err
	}
	return &FileStreamStorageProvisioner{
		config: config,
	}, nil
}

// AddFlags adds flags.
func (p *FileStreamStorageProvisioner) AddFlags(flagSet *flag.FlagSet) error {
	err := azconfigs.AddFlagsForCommon(flagSet)
	if err != nil {
		return err
	}
	flagSet.Bool(flagUp, false, "provision the database")
	flagSet.Bool(flagDown, false, "deprovision the database")
	err = p.config.AddFlags(flagSet)
	if err != nil {
		return err
	}
	return nil
}

// InitFromViper initializes the configuration from viper.
func (p *FileStreamStorageProvisioner) InitFromViper(v *viper.Viper) error {
	debug, logLevel, err := azconfigs.InitFromViperForCommon(v)
	if err != nil {
		return err
	}
	p.debug = debug
	p.logLevel = logLevel
	p.up = v.GetBool(flagUp)
	p.down = v.GetBool(flagDown)
	err = p.config.InitFromViper(v)
	if err != nil {
		return err
	}
	p.logger, err = azconfigs.NewLogger(p.debug, p.logLevel)
	if err != nil {
		return err
	}
	return nil
}

// Up provisions the database.
func (p *FileStreamStorageProvisioner) Up() error {
	if !p.up {
		p.logger.Info("Database provisioning skipped")
		return nil
	}
	p.logger.Debug("Provisioning database")
	p.logger.Info("Database provisioned")
	return nil
}

// Down deprovisions the database.
func (p *FileStreamStorageProvisioner) Down() error {
	if !p.down {
		p.logger.Info("Database deprovisioning skipped")
		return nil
	}
	p.logger.Debug("Deprovisioning database")
	p.logger.Info("Database deprovisioned")
	return nil
}
