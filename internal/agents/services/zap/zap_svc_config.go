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
	"errors"
	"flag"

	"github.com/spf13/viper"

	"github.com/permguard/permguard/common/pkg/extensions/copier"
	"github.com/permguard/permguard/common/pkg/extensions/validators"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	flagStorageZAPPrefix      = "storage-zap"
	flagServerZAPPrefix       = "server-zap"
	flagSuffixGrpcPort        = "grpc-port"
	flagCentralEngine         = "engine-central"
	flagDataFetchMaxPageSize  = "data-fetch-maxpagesize"
	flagEnableDefaultCreation = "data-enable-default-creation"
)

// ServiceConfig holds the configuration for the server.
type ServiceConfig struct {
	serviceKind services.ServiceKind
	config      map[string]any
}

// NewServiceConfig creates a new server factory configuration.
func NewServiceConfig() (*ServiceConfig, error) {
	return &ServiceConfig{
		serviceKind: services.ServiceZAP,
		config:      map[string]any{},
	}, nil
}

// AddFlags adds flags.
func (c *ServiceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.Int(options.FlagName(flagServerZAPPrefix, flagSuffixGrpcPort), 9091, "port to be used for exposing the zap grpc services")
	flagSet.String(options.FlagName(flagStorageZAPPrefix, flagCentralEngine), "", "data storage engine to be used for central data; this overrides the --storage-engine-central option")
	flagSet.Int(options.FlagName(flagServerZAPPrefix, flagDataFetchMaxPageSize), 10000, "maximum number of items to fetch per request")
	flagSet.Bool(options.FlagName(flagServerZAPPrefix, flagEnableDefaultCreation), false, "the creation of default entities during data creation")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *ServiceConfig) InitFromViper(v *viper.Viper) error {
	// retrieve the grpc port
	flagName := options.FlagName(flagServerZAPPrefix, flagSuffixGrpcPort)
	grpcPort := v.GetInt(flagName)
	if !validators.IsValidPort(grpcPort) {
		return errors.New("zap-service: invalid port")
	}
	c.config[flagSuffixGrpcPort] = grpcPort
	// retrieve the data fetch max page size
	flagName = options.FlagName(flagServerZAPPrefix, flagCentralEngine)
	centralStorageEngine := v.GetString(flagName)
	storageCEng, err := storage.NewStorageKindFromString(centralStorageEngine)
	if err != nil {
		return errors.Join(errors.New("zap-service: invalid central storage engine"), err)
	}
	c.config[flagCentralEngine] = storageCEng
	// retrieve the data fetch max page size
	flagName = options.FlagName(flagServerZAPPrefix, flagDataFetchMaxPageSize)
	dataFetchMaxPageSize := v.GetInt(flagName)
	if dataFetchMaxPageSize <= 0 {
		return errors.New("zap-service: invalid data fetch max page size")
	}
	c.config[flagDataFetchMaxPageSize] = dataFetchMaxPageSize
	// retrieve the enable default creation
	flagName = options.FlagName(flagServerZAPPrefix, flagEnableDefaultCreation)
	enableDefaultCreation := v.GetBool(flagName)
	c.config[flagEnableDefaultCreation] = enableDefaultCreation
	return nil
}

// ConfigData returns the configuration data.
func (c *ServiceConfig) ConfigData() map[string]any {
	return copier.CopyMap(c.config)
}

// Port returns the port.
func (c *ServiceConfig) Port() int {
	return c.config[flagSuffixGrpcPort].(int)
}

// StorageCentralEngine returns the storage central engine.
func (c *ServiceConfig) StorageCentralEngine() storage.Kind {
	return c.config[flagCentralEngine].(storage.Kind)
}

// DataFetchMaxPageSize returns the maximum number of items to fetch per request.
func (c *ServiceConfig) DataFetchMaxPageSize() int {
	return c.config[flagDataFetchMaxPageSize].(int)
}

// EnabledDefaultCreation return if the default creation is enabled.
func (c *ServiceConfig) EnabledDefaultCreation() bool {
	return c.config[flagEnableDefaultCreation].(bool)
}

// Service returns the service kind.
func (c *ServiceConfig) Service() services.ServiceKind {
	return c.serviceKind
}
