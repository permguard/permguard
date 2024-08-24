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

	azservices "github.com/permguard/permguard/pkg/agents/services"
	azconfigs "github.com/permguard/permguard/pkg/configs"
	azvalidators "github.com/permguard/permguard/pkg/extensions/validators"
)

const (
	flagServerPAPPrefix = "server.pap"
	flagSuffixGrpcPort  = "grpc.port"
	flagSuffixHTTPPort  = "http.port"
    flagDataFetchMaxPageSize        = "data.fetch.maxpagesize"
)

// PAPServiceConfig holds the configuration for the server.
type PAPServiceConfig struct {
	service azservices.ServiceKind
	port    int
}

// NewPAPServiceConfig creates a new server factory configuration.
func NewPAPServiceConfig() (*PAPServiceConfig, error) {
	return &PAPServiceConfig{
		service: azservices.ServicePAP,
	}, nil
}

// AddFlags adds flags.
func (c *PAPServiceConfig) AddFlags(flagSet *flag.FlagSet) error {
	flagSet.Int(azconfigs.FlagName(flagServerPAPPrefix, flagSuffixGrpcPort), 9092, "port to be used for exposing the pap grpc services")
	flagSet.Int(azconfigs.FlagName(flagServerPAPPrefix, flagSuffixHTTPPort), 8082, "port to be used for exposing the pap http services")
	flagSet.Int(azconfigs.FlagName(flagServerPAPPrefix, flagDataFetchMaxPageSize), 10000, "maximum number of items to fetch per request")
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *PAPServiceConfig) InitFromViper(v *viper.Viper) error {
	c.port = v.GetInt(azconfigs.FlagName(flagServerPAPPrefix, flagSuffixGrpcPort))
	if !azvalidators.IsValidPort(c.port) {
		return azservices.ErrServiceInvalidPort
	}
	return nil
}

// GetPort returns the port.
func (c *PAPServiceConfig) GetPort() int {
	return c.port
}

// GetService returns the service kind.
func (c *PAPServiceConfig) GetService() azservices.ServiceKind {
	return c.service
}
