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

package pdp

import (
	"errors"
	"flag"

	"github.com/spf13/viper"

	"github.com/permguard/permguard/common/pkg/extensions/copier"
	"github.com/permguard/permguard/common/pkg/extensions/validators"
	"github.com/permguard/permguard/internal/agents/decisions"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	flagStoragePDPPrefix     = "storage-pdp"
	flagServerPDPPrefix      = "server-pdp"
	flagSuffixGrpcPort       = "grpc-port"
	flagCentralEngine        = "engine-central"
	flagDataFetchMaxPageSize = "data-fetch-maxpagesize"
	flagSuffixDecisionLog    = "decision-log"
)

// ServiceConfig holds the configuration for the server.
type ServiceConfig struct {
	service services.ServiceKind
	config  map[string]any
}

// NewServiceConfig creates a new server factory configuration.
func NewServiceConfig() (*ServiceConfig, error) {
	return &ServiceConfig{
		service: services.ServicePDP,
		config:  map[string]any{},
	}, nil
}

// AddFlags adds flags.
func (c *ServiceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.Int(options.FlagName(flagServerPDPPrefix, flagSuffixGrpcPort), 9094, "port to be used for exposing the pdp grpc services")
	flagSet.String(options.FlagName(flagStoragePDPPrefix, flagCentralEngine), "", "data storage engine to be used for central data; this overrides the --storage-engine-central option")
	flagSet.Int(options.FlagName(flagServerPDPPrefix, flagDataFetchMaxPageSize), 10000, "maximum number of items to fetch per request")
	flagSet.String(options.FlagName(flagServerPDPPrefix, flagSuffixDecisionLog), decisions.DecisionLogNone.String(), "specifies where to send decision logs output type")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *ServiceConfig) InitFromViper(v *viper.Viper) error {
	// retrieve the grpc port
	flagName := options.FlagName(flagServerPDPPrefix, flagSuffixGrpcPort)
	grpcPort := v.GetInt(flagName)
	if !validators.IsValidPort(grpcPort) {
		return errors.New("pdp-service: invalid port")
	}
	c.config[flagSuffixGrpcPort] = grpcPort
	// retrieve the central storage engine
	flagName = options.FlagName(flagServerPDPPrefix, flagCentralEngine)
	centralStorageEngine := v.GetString(flagName)
	storageCEng, err := storage.NewStorageKindFromString(centralStorageEngine)
	if err != nil {
		return errors.Join(errors.New("pdp-service: invalid central storage engine"), err)
	}
	c.config[flagCentralEngine] = storageCEng
	// retrieve the data fetch max page size
	flagName = options.FlagName(flagServerPDPPrefix, flagDataFetchMaxPageSize)
	dataFetchMaxPageSize := v.GetInt(flagName)
	if dataFetchMaxPageSize <= 0 {
		return errors.New("pdp-service: invalid data fetch max page size")
	}
	c.config[flagDataFetchMaxPageSize] = dataFetchMaxPageSize
	// retrieve the decision log
	flagName = options.FlagName(flagServerPDPPrefix, flagSuffixDecisionLog)
	decisionLog := v.GetString(flagName)
	decisionLogType, err := decisions.NewDecisionLogKindFromString(decisionLog)
	if err != nil {
		return errors.Join(errors.New("pdp-service: invalid decision log"), err)
	}
	c.config[flagSuffixDecisionLog] = decisionLogType
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

// DecisionLog returns the decision log.
func (c *ServiceConfig) DecisionLog() string {
	return c.config[flagSuffixDecisionLog].(string)
}

// Service returns the service kind.
func (c *ServiceConfig) Service() services.ServiceKind {
	return c.service
}
