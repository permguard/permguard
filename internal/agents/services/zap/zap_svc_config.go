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

package zap

import (
	"flag"

	"github.com/spf13/viper"

	azcopier "github.com/permguard/permguard/common/pkg/extensions/copier"
	azvalidators "github.com/permguard/permguard/common/pkg/extensions/validators"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	flagStorageZAPPrefix      = "storage-zap"
	flagServerZAPPrefix       = "server-zap"
	flagSuffixGrpcPort        = "grpc-port"
	flagCentralEngine         = "engine-central"
	flagDataFetchMaxPageSize  = "data-fetch-maxpagesize"
	flagEnableDefaultCreation = "data-enable-default-creation"
)

// ZAPServiceConfig holds the configuration for the server.
type ZAPServiceConfig struct {
	serviceKind azservices.ServiceKind
	config      map[string]any
}

// NewZAPServiceConfig creates a new server factory configuration.
func NewZAPServiceConfig() (*ZAPServiceConfig, error) {
	return &ZAPServiceConfig{
		serviceKind: azservices.ServiceZAP,
		config:      map[string]any{},
	}, nil
}

// AddFlags adds flags.
func (c *ZAPServiceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.Int(azoptions.FlagName(flagServerZAPPrefix, flagSuffixGrpcPort), 9091, "port to be used for exposing the zap grpc services")
	flagSet.String(azoptions.FlagName(flagStorageZAPPrefix, flagCentralEngine), "", "data storage engine to be used for central data; this overrides the --storage-engine-central option")
	flagSet.Int(azoptions.FlagName(flagServerZAPPrefix, flagDataFetchMaxPageSize), 10000, "maximum number of items to fetch per request")
	flagSet.Bool(azoptions.FlagName(flagServerZAPPrefix, flagEnableDefaultCreation), false, "the creation of default entities (e.g., tenants, identity sources) during data creation")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *ZAPServiceConfig) InitFromViper(v *viper.Viper) error {
	// retrieve the grpc port
	flagName := azoptions.FlagName(flagServerZAPPrefix, flagSuffixGrpcPort)
	grpcPort := v.GetInt(flagName)
	if !azvalidators.IsValidPort(grpcPort) {
		return azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliArguments, "invalid port")
	}
	c.config[flagSuffixGrpcPort] = grpcPort
	// retrieve the data fetch max page size
	flagName = azoptions.FlagName(flagServerZAPPrefix, flagCentralEngine)
	centralStorageEngine := v.GetString(flagName)
	storageCEng, err := azstorage.NewStorageKindFromString(centralStorageEngine)
	if err != nil {
		return azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "invalid central sotrage engine", err)
	}
	c.config[flagCentralEngine] = storageCEng
	// retrieve the data fetch max page size
	flagName = azoptions.FlagName(flagServerZAPPrefix, flagDataFetchMaxPageSize)
	dataFetchMaxPageSize := v.GetInt(flagName)
	if dataFetchMaxPageSize <= 0 {
		return azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliArguments, "invalid data fetch max page size")
	}
	c.config[flagDataFetchMaxPageSize] = dataFetchMaxPageSize
	// retrieve the enable default creation
	flagName = azoptions.FlagName(flagServerZAPPrefix, flagEnableDefaultCreation)
	enableDefaultCreation := v.GetBool(flagName)
	c.config[flagEnableDefaultCreation] = enableDefaultCreation
	return nil
}

// GetConfigData returns the configuration data.
func (c *ZAPServiceConfig) GetConfigData() map[string]any {
	return azcopier.CopyMap(c.config)
}

// GetPort returns the port.
func (c *ZAPServiceConfig) GetPort() int {
	return c.config[flagSuffixGrpcPort].(int)
}

// GetStorageCentralEngine returns the storage central engine.
func (c *ZAPServiceConfig) GetStorageCentralEngine() azstorage.StorageKind {
	return c.config[flagCentralEngine].(azstorage.StorageKind)
}

// GetDataFetchMaxPageSize returns the maximum number of items to fetch per request.
func (c *ZAPServiceConfig) GetDataFetchMaxPageSize() int {
	return c.config[flagDataFetchMaxPageSize].(int)
}

// GetEnabledDefaultCreation return if the default creation is enabled.
func (c *ZAPServiceConfig) GetEnabledDefaultCreation() bool {
	return c.config[flagEnableDefaultCreation].(bool)
}

// GetService returns the service kind.
func (c *ZAPServiceConfig) GetService() azservices.ServiceKind {
	return c.serviceKind
}
