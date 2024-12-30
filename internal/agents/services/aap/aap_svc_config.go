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

package aap

import (
	"flag"

	"github.com/spf13/viper"

	azcopier "github.com/permguard/permguard-core/pkg/extensions/copier"
	azvalidators "github.com/permguard/permguard-core/pkg/extensions/validators"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	flagStorageAAPPrefix      = "storage.aap"
	flagServerAAPPrefix       = "server.aap"
	flagSuffixGrpcPort        = "grpc.port"
	flagCentralEngine         = "engine.central"
	flagDataFetchMaxPageSize  = "data.fetch.maxpagesize"
	flagEnableDefaultCreation = "data.enable.default.creation"
)

// AAPServiceConfig holds the configuration for the server.
type AAPServiceConfig struct {
	serviceKind azservices.ServiceKind
	config      map[string]any
}

// NewAAPServiceConfig creates a new server factory configuration.
func NewAAPServiceConfig() (*AAPServiceConfig, error) {
	return &AAPServiceConfig{
		serviceKind: azservices.ServiceAAP,
		config:      map[string]any{},
	}, nil
}

// AddFlags adds flags.
func (c *AAPServiceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.Int(azoptions.FlagName(flagServerAAPPrefix, flagSuffixGrpcPort), 9091, "port to be used for exposing the aap grpc services")
	flagSet.String(azoptions.FlagName(flagStorageAAPPrefix, flagCentralEngine), "", "data storage engine to be used for central data; this overrides the --storage.engine.central option")
	flagSet.Int(azoptions.FlagName(flagServerAAPPrefix, flagDataFetchMaxPageSize), 10000, "maximum number of items to fetch per request")
	flagSet.Bool(azoptions.FlagName(flagServerAAPPrefix, flagEnableDefaultCreation), false, "the creation of default entities (e.g., tenants, identity sources) during data creation")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *AAPServiceConfig) InitFromViper(v *viper.Viper) error {
	// retrieve the grpc port
	flagName := azoptions.FlagName(flagServerAAPPrefix, flagSuffixGrpcPort)
	grpcPort := v.GetInt(flagName)
	if !azvalidators.IsValidPort(grpcPort) {
		return azerrors.WrapSystemError(azerrors.ErrCliArguments, "core: invalid port")
	}
	c.config[flagSuffixGrpcPort] = grpcPort
	// retrieve the data fetch max page size
	flagName = azoptions.FlagName(flagServerAAPPrefix, flagCentralEngine)
	centralStorageEngine := v.GetString(flagName)
	if len(centralStorageEngine) == 0 {
		return azerrors.WrapSystemError(azerrors.ErrCliArguments, "core: invalid central sotrage engine")
	}
	c.config[flagCentralEngine] = centralStorageEngine
	// retrieve the data fetch max page size
	flagName = azoptions.FlagName(flagServerAAPPrefix, flagDataFetchMaxPageSize)
	dataFetchMaxPageSize := v.GetInt(flagName)
	if dataFetchMaxPageSize <= 0 {
		return azerrors.WrapSystemError(azerrors.ErrCliArguments, "core: invalid data fetch max page size")
	}
	c.config[flagDataFetchMaxPageSize] = dataFetchMaxPageSize
	// retrieve the enable default creation
	flagName = azoptions.FlagName(flagServerAAPPrefix, flagEnableDefaultCreation)
	enableDefaultCreation := v.GetBool(flagName)
	c.config[flagEnableDefaultCreation] = enableDefaultCreation
	return nil
}

// GetConfigData returns the configuration data.
func (c *AAPServiceConfig) GetConfigData() map[string]any {
	return azcopier.CopyMap(c.config)
}

// GetPort returns the port.
func (c *AAPServiceConfig) GetPort() int {
	return c.config[flagSuffixGrpcPort].(int)
}

// GetStorageCentralEngine returns the storage central engine.
func (c *AAPServiceConfig) GetStorageCentralEngine() string {
	return c.config[flagCentralEngine].(string)
}

// GetDataFetchMaxPageSize returns the maximum number of items to fetch per request.
func (c *AAPServiceConfig) GetDataFetchMaxPageSize() int {
	return c.config[flagDataFetchMaxPageSize].(int)
}

// GetEnabledDefaultCreation return if the default creation is enabled.
func (c *AAPServiceConfig) GetEnabledDefaultCreation() bool {
	return c.config[flagEnableDefaultCreation].(bool)
}

// GetService returns the service kind.
func (c *AAPServiceConfig) GetService() azservices.ServiceKind {
	return c.serviceKind
}
