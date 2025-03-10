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

package pap

import (
	"flag"

	"github.com/spf13/viper"

	azcopier "github.com/permguard/permguard-core/pkg/extensions/copier"
	azvalidators "github.com/permguard/permguard-core/pkg/extensions/validators"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	flagStoragePAPPrefix     = "storage-pap"
	flagServerPAPPrefix      = "server-pap"
	flagSuffixGrpcPort       = "grpc-port"
	flagCentralEngine        = "engine-central"
	flagDataFetchMaxPageSize = "data-fetch-maxpagesize"
)

// PAPServiceConfig holds the configuration for the server.
type PAPServiceConfig struct {
	service azservices.ServiceKind
	config  map[string]any
}

// NewPAPServiceConfig creates a new server factory configuration.
func NewPAPServiceConfig() (*PAPServiceConfig, error) {
	return &PAPServiceConfig{
		service: azservices.ServicePAP,
		config:  map[string]any{},
	}, nil
}

// AddFlags adds flags.
func (c *PAPServiceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.Int(azoptions.FlagName(flagServerPAPPrefix, flagSuffixGrpcPort), 9092, "port to be used for exposing the pap grpc services")
	flagSet.String(azoptions.FlagName(flagStoragePAPPrefix, flagCentralEngine), "", "data storage engine to be used for central data; this overrides the --storage-engine-central option")
	flagSet.Int(azoptions.FlagName(flagServerPAPPrefix, flagDataFetchMaxPageSize), 10000, "maximum number of items to fetch per request")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *PAPServiceConfig) InitFromViper(v *viper.Viper) error {
	// retrieve the grpc port
	flagName := azoptions.FlagName(flagServerPAPPrefix, flagSuffixGrpcPort)
	grpcPort := v.GetInt(flagName)
	if !azvalidators.IsValidPort(grpcPort) {
		return azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliArguments, "invalid port")
	}
	c.config[flagSuffixGrpcPort] = grpcPort
	// retrieve the data fetch max page size
	flagName = azoptions.FlagName(flagServerPAPPrefix, flagCentralEngine)
	centralStorageEngine := v.GetString(flagName)
	storageCEng, err := azstorage.NewStorageKindFromString(centralStorageEngine)
	if err != nil {
		return azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "invalid central sotrage engine", err)
	}
	c.config[flagCentralEngine] = storageCEng
	// retrieve the data fetch max page size
	flagName = azoptions.FlagName(flagServerPAPPrefix, flagDataFetchMaxPageSize)
	dataFetchMaxPageSize := v.GetInt(flagName)
	if dataFetchMaxPageSize <= 0 {
		return azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliArguments, "invalid data fetch max page size")
	}
	c.config[flagDataFetchMaxPageSize] = dataFetchMaxPageSize
	return nil
}

// GetConfigData returns the configuration data.
func (c *PAPServiceConfig) GetConfigData() map[string]any {
	return azcopier.CopyMap(c.config)
}

// GetPort returns the port.
func (c *PAPServiceConfig) GetPort() int {
	return c.config[flagSuffixGrpcPort].(int)
}

// GetStorageCentralEngine returns the storage central engine.
func (c *PAPServiceConfig) GetStorageCentralEngine() azstorage.StorageKind {
	return c.config[flagCentralEngine].(azstorage.StorageKind)
}

// GetDataFetchMaxPageSize returns the maximum number of items to fetch per request.
func (c *PAPServiceConfig) GetDataFetchMaxPageSize() int {
	return c.config[flagDataFetchMaxPageSize].(int)
}

// GetService returns the service kind.
func (c *PAPServiceConfig) GetService() azservices.ServiceKind {
	return c.service
}
