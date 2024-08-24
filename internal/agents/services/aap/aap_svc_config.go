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

	azservices "github.com/permguard/permguard/pkg/agents/services"
	azconfigs "github.com/permguard/permguard/pkg/configs"
	azvalidators "github.com/permguard/permguard/pkg/extensions/validators"
)

const (
	flagServerAAPPrefix       = "server.aap"
	flagSuffixGrpcPort        = "grpc.port"
	flagSuffixHTTPPort        = "http.port"
	flagDataFetchMaxPageSize  = "data.fetch.maxpagesize"
	flagEnableDefaultCreation = "enable.default.creation"
)

// AAPServiceConfig holds the configuration for the server.
type AAPServiceConfig struct {
	serviceKind azservices.ServiceKind
	port        int
}

// NewAAPServiceConfig creates a new server factory configuration.
func NewAAPServiceConfig() (*AAPServiceConfig, error) {
	return &AAPServiceConfig{
		serviceKind: azservices.ServiceAAP,
	}, nil
}

// AddFlags adds flags.
func (c *AAPServiceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.Int(azconfigs.FlagName(flagServerAAPPrefix, flagSuffixGrpcPort), 9091, "port to be used for exposing the aap grpc services")
	flagSet.Int(azconfigs.FlagName(flagServerAAPPrefix, flagSuffixHTTPPort), 8081, "port to be used for exposing the aap http services")
	flagSet.Int(azconfigs.FlagName(flagServerAAPPrefix, flagDataFetchMaxPageSize), 10000, "maximum number of items to fetch per request")
	flagSet.Bool(azconfigs.FlagName(flagServerAAPPrefix, flagEnableDefaultCreation), false, "the creation of default entities (e.g., tenants, identity sources) during data creation")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *AAPServiceConfig) InitFromViper(v *viper.Viper) error {
	c.port = v.GetInt(azconfigs.FlagName(flagServerAAPPrefix, flagSuffixGrpcPort))
	if !azvalidators.IsValidPort(c.port) {
		return azservices.ErrServiceInvalidPort
	}
	return nil
}

// GetPort returns the port.
func (c *AAPServiceConfig) GetPort() int {
	return c.port
}

// GetService returns the service kind.
func (c *AAPServiceConfig) GetService() azservices.ServiceKind {
	return c.serviceKind
}
