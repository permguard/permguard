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

	azservices "github.com/permguard/permguard/pkg/agents/services"
	azconfigs "github.com/permguard/permguard/pkg/configs"
	azvalidators "github.com/permguard/permguard/pkg/extensions/validators"
)

const (
	flagServerPDPPrefix = "server.pdp"
	flagSuffixGrpcPort  = "grpc.port"
	flagSuffixHTTPPort  = "http.port"
    flagDataFetchMaxPageSize        = "data.fetch.maxpagesize"
    flagEnableDefaultCreation       = "enable.default.creation"
)

// PDPServiceConfig holds the configuration for the server.
type PDPServiceConfig struct {
	service azservices.ServiceKind
	port    int
}

// NewPDPServiceConfig creates a new server factory configuration.
func NewPDPServiceConfig() (*PDPServiceConfig, error) {
	return &PDPServiceConfig{
		service: azservices.ServicePDP,
	}, nil
}

// AddFlags adds flags.
func (c *PDPServiceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.Int(azconfigs.FlagName(flagServerPDPPrefix, flagSuffixGrpcPort), 9096, "port to be used for exposing the pdp grpc services")
	flagSet.Int(azconfigs.FlagName(flagServerPDPPrefix, flagSuffixHTTPPort), 8086, "port to be used for exposing the pdp http services")
	flagSet.Int(azconfigs.FlagName(flagServerPDPPrefix, flagDataFetchMaxPageSize), 10000, "maximum number of items to fetch per request")
	flagSet.Bool(azconfigs.FlagName(flagServerPDPPrefix, flagEnableDefaultCreation), false, "enable the creation of default relationships during data creation")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *PDPServiceConfig) InitFromViper(v *viper.Viper) error {
	c.port = v.GetInt(azconfigs.FlagName(flagServerPDPPrefix, flagSuffixGrpcPort))
	if !azvalidators.IsValidPort(c.port) {
		return azservices.ErrServiceInvalidPort
	}
	return nil
}

// GetPort returns the port.
func (c *PDPServiceConfig) GetPort() int {
	return c.port
}

// GetService returns the service kind.
func (c *PDPServiceConfig) GetService() azservices.ServiceKind {
	return c.service
}
