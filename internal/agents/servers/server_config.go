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

package servers

import (
	"errors"
	"flag"

	"github.com/spf13/viper"

	"github.com/permguard/permguard/common/pkg/extensions/copier"
	"github.com/permguard/permguard/common/pkg/extensions/validators"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/cli/options"
	"github.com/permguard/permguard/pkg/transport/grpctls"
)

const (
	flagPrefixServer            = "server"
	flagSuffixAppData           = "appdata"
	flagSuffixNOTPMaxPacketSize = "notp-max-packet-size"
	flagSuffixOTelEnabled       = "otel-enabled"
	flagSuffixOTelEndpoint      = "otel-endpoint"
	flagSuffixOTelSampleRate    = "otel-sample-rate"
	flagSuffixTLSMode           = "tls-mode"
	flagSuffixTLSCertFile       = "tls-cert-file"
	flagSuffixTLSKeyFile        = "tls-key-file"
	flagSuffixTLSCAFile         = "tls-ca-file"
	flagSuffixTLSAutoCertDir    = "tls-auto-cert-dir"
)

// ServerConfig holds the configuration for the server.
type ServerConfig struct {
	displayName          string
	debug                bool
	logLevel             string
	appData              string
	notpMaxPacketSize    int
	otelEnabled          bool
	otelEndpoint         string
	otelSampleRate       float64
	tlsMode              string
	tlsCertFile          string
	tlsKeyFile           string
	tlsCAFile            string
	tlsAutoCertDir       string
	centralStorageEngine storage.Kind
	storages             []storage.Kind
	storagesFactories    map[storage.Kind]storage.FactoryProvider
	services             []services.ServiceKind
	servicesFactories    map[services.ServiceKind]services.ServiceFactoryProvider
}

// newServerConfig creates a new server factory configuration.
func newServerConfig(displayName string, centralStorageEngine storage.Kind,
	storages []storage.Kind, storagesFactories map[storage.Kind]storage.FactoryProvider,
	services []services.ServiceKind, servicesFactories map[services.ServiceKind]services.ServiceFactoryProvider,
) *ServerConfig {
	return &ServerConfig{
		displayName:          displayName,
		centralStorageEngine: centralStorageEngine,
		storages:             copier.CopySlice(storages),
		storagesFactories:    copier.CopyMap(storagesFactories),
		services:             copier.CopySlice(services),
		servicesFactories:    copier.CopyMap(servicesFactories),
	}
}

// DisplayName returns the display name.
func (c *ServerConfig) DisplayName() string {
	return c.displayName
}

// CentralStorageEngine returns the central storage engine.
func (c *ServerConfig) CentralStorageEngine() storage.Kind {
	return c.centralStorageEngine
}

// Storages returns service kinds.
func (c *ServerConfig) Storages() []storage.Kind {
	return copier.CopySlice(c.storages)
}

// StoragesFactories returns factories.
func (c *ServerConfig) StoragesFactories() map[storage.Kind]storage.FactoryProvider {
	return copier.CopyMap(c.storagesFactories)
}

// Services returns service kinds.
func (c *ServerConfig) Services() []services.ServiceKind {
	return copier.CopySlice(c.services)
}

// ServicesFactories returns factories.
func (c *ServerConfig) ServicesFactories() map[services.ServiceKind]services.ServiceFactoryProvider {
	return copier.CopyMap(c.servicesFactories)
}

// AppData returns the zone data.
func (c *ServerConfig) AppData() string {
	return c.appData
}

// NOTPMaxPacketSize returns the notp maximum packet size in bytes.
func (c *ServerConfig) NOTPMaxPacketSize() int {
	return c.notpMaxPacketSize
}

// OTelEnabled returns whether OpenTelemetry is enabled.
func (c *ServerConfig) OTelEnabled() bool {
	return c.otelEnabled
}

// OTelEndpoint returns the OpenTelemetry collector endpoint.
func (c *ServerConfig) OTelEndpoint() string {
	return c.otelEndpoint
}

// OTelSampleRate returns the OpenTelemetry trace sample rate.
func (c *ServerConfig) OTelSampleRate() float64 {
	return c.otelSampleRate
}

// TLSConfig returns the TLS server configuration.
func (c *ServerConfig) TLSConfig() *grpctls.ServerConfig {
	mode, _ := grpctls.ParseMode(c.tlsMode)
	return &grpctls.ServerConfig{
		Mode:        mode,
		CertFile:    c.tlsCertFile,
		KeyFile:     c.tlsKeyFile,
		CAFile:      c.tlsCAFile,
		AutoCertDir: c.tlsAutoCertDir,
	}
}

// AddFlags adds flags.
func (c *ServerConfig) AddFlags(flagSet *flag.FlagSet) error {
	err := options.AddFlagsForCommon(flagSet)
	if err != nil {
		return err
	}
	flagSet.String(options.FlagName(flagPrefixServer, flagSuffixAppData), "./", "directory to be used as zone data")
	flagSet.Int(options.FlagName(flagPrefixServer, flagSuffixNOTPMaxPacketSize), 16777216, "notp maximum packet size in bytes (default 16MB)")
	flagSet.Bool(options.FlagName(flagPrefixServer, flagSuffixOTelEnabled), false, "enable OpenTelemetry tracing and metrics")
	flagSet.String(options.FlagName(flagPrefixServer, flagSuffixOTelEndpoint), "localhost:4317", "OpenTelemetry collector gRPC endpoint")
	flagSet.Float64(options.FlagName(flagPrefixServer, flagSuffixOTelSampleRate), 0.1, "OpenTelemetry trace sample rate (0.0 to 1.0)")
	flagSet.String(options.FlagName(flagPrefixServer, flagSuffixTLSMode), "none", "TLS mode: none, tls, mtls, external")
	flagSet.String(options.FlagName(flagPrefixServer, flagSuffixTLSCertFile), "", "path to TLS server certificate file (PEM)")
	flagSet.String(options.FlagName(flagPrefixServer, flagSuffixTLSKeyFile), "", "path to TLS server private key file (PEM)")
	flagSet.String(options.FlagName(flagPrefixServer, flagSuffixTLSCAFile), "", "path to CA certificate for client verification (PEM)")
	flagSet.String(options.FlagName(flagPrefixServer, flagSuffixTLSAutoCertDir), "", "directory for auto-generated TLS certificates (mode=tls only)")
	for _, fcty := range c.storagesFactories {
		config, _ := fcty.FactoryConfig()
		err = config.AddFlags(flagSet)
		if err != nil {
			return err
		}
	}
	for _, fcty := range c.servicesFactories {
		config, _ := fcty.FactoryConfig()
		err = config.AddFlags(flagSet)
		if err != nil {
			return err
		}
	}
	return nil
}

// InitFromViper initializes the configuration from viper.
func (c *ServerConfig) InitFromViper(v *viper.Viper) error {
	debug, logLevel, err := options.InitFromViperForCommon(v)
	if err != nil {
		return err
	}
	c.debug = debug
	c.logLevel = logLevel
	c.appData = v.GetString(options.FlagName(flagPrefixServer, flagSuffixAppData))
	if !validators.IsValidPath(c.appData) {
		return errors.New("server: invalid app data directory")
	}
	c.notpMaxPacketSize = v.GetInt(options.FlagName(flagPrefixServer, flagSuffixNOTPMaxPacketSize))
	if c.notpMaxPacketSize <= 0 {
		return errors.New("server: invalid notp max packet size")
	}
	c.otelEnabled = v.GetBool(options.FlagName(flagPrefixServer, flagSuffixOTelEnabled))
	c.otelEndpoint = v.GetString(options.FlagName(flagPrefixServer, flagSuffixOTelEndpoint))
	if c.otelEnabled && len(c.otelEndpoint) == 0 {
		return errors.New("server: otel endpoint must be set when otel is enabled")
	}
	c.otelSampleRate = v.GetFloat64(options.FlagName(flagPrefixServer, flagSuffixOTelSampleRate))
	if c.otelSampleRate < 0 || c.otelSampleRate > 1 {
		return errors.New("server: otel sample rate must be between 0.0 and 1.0")
	}
	c.tlsMode = v.GetString(options.FlagName(flagPrefixServer, flagSuffixTLSMode))
	if _, err := grpctls.ParseMode(c.tlsMode); err != nil {
		return err
	}
	c.tlsCertFile = v.GetString(options.FlagName(flagPrefixServer, flagSuffixTLSCertFile))
	c.tlsKeyFile = v.GetString(options.FlagName(flagPrefixServer, flagSuffixTLSKeyFile))
	c.tlsCAFile = v.GetString(options.FlagName(flagPrefixServer, flagSuffixTLSCAFile))
	c.tlsAutoCertDir = v.GetString(options.FlagName(flagPrefixServer, flagSuffixTLSAutoCertDir))
	if err := c.TLSConfig().Validate(); err != nil {
		return err
	}
	for _, fcty := range c.storagesFactories {
		config, err := fcty.FactoryConfig()
		if err != nil {
			return err
		}
		err = config.InitFromViper(v)
		if err != nil {
			return err
		}
	}
	for _, fcty := range c.servicesFactories {
		config, err := fcty.FactoryConfig()
		if err != nil {
			return err
		}
		err = config.InitFromViper(v)
		if err != nil {
			return err
		}
	}
	return nil
}
