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
	"flag"

	"github.com/spf13/viper"

	azcopier "github.com/permguard/permguard-core/pkg/extensions/copier"
	azvalidators "github.com/permguard/permguard-core/pkg/extensions/validators"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	flagServerPDPPrefix      = "server.pdp"
	flagSuffixGrpcPort       = "grpc.port"
	flagDataFetchMaxPageSize = "data.fetch.maxpagesize"
)

// PDPServiceConfig holds the configuration for the server.
type PDPServiceConfig struct {
	service azservices.ServiceKind
	config  map[string]interface{}
}

// NewPDPServiceConfig creates a new server factory configuration.
func NewPDPServiceConfig() (*PDPServiceConfig, error) {
	return &PDPServiceConfig{
		service: azservices.ServicePDP,
		config:  map[string]interface{}{},
	}, nil
}

// AddFlags adds flags.
func (c *PDPServiceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.Int(azoptions.FlagName(flagServerPDPPrefix, flagSuffixGrpcPort), 9096, "port to be used for exposing the pdp grpc services")
	flagSet.Int(azoptions.FlagName(flagServerPDPPrefix, flagDataFetchMaxPageSize), 10000, "maximum number of items to fetch per request")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *PDPServiceConfig) InitFromViper(v *viper.Viper) error {
	// retrieve the grpc port
	flagName := azoptions.FlagName(flagServerPDPPrefix, flagSuffixGrpcPort)
	grpcPort := v.GetInt(flagName)
	if !azvalidators.IsValidPort(grpcPort) {
		return azservices.ErrServiceInvalidPort
	}
	c.config[flagSuffixGrpcPort] = grpcPort
	// retrieve the data fetch max page size
	flagName = azoptions.FlagName(flagServerPDPPrefix, flagDataFetchMaxPageSize)
	dataFetchMaxPageSize := v.GetInt(flagName)
	if dataFetchMaxPageSize <= 0 {
		return azservices.ErrServiceInvalidDataFetchPageSize
	}
	c.config[flagDataFetchMaxPageSize] = dataFetchMaxPageSize
	return nil
}

// GetConfigData returns the configuration data.
func (c *PDPServiceConfig) GetConfigData() map[string]interface{} {
	return azcopier.CopyMap(c.config)
}

// GetPort returns the port.
func (c *PDPServiceConfig) GetPort() int {
	return c.config[flagSuffixGrpcPort].(int)
}

// GetService returns the service kind.
func (c *PDPServiceConfig) GetService() azservices.ServiceKind {
	return c.service
}
