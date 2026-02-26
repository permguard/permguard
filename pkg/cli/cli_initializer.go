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

package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/pkg/authz/languages"
	"github.com/permguard/permguard/pkg/transport/clients"
)

// DependenciesProvider is the cli dependencies provider.
type DependenciesProvider interface {
	// CreatePrinter creates a new printer.
	CreatePrinter(verbose bool, output string) (Printer, error)
	// CreateGrpcZAPClient creates a new gRPC client for the ZAP service.
	CreateGrpcZAPClient(zapTarget string) (clients.GrpcZAPClient, error)
	// CreateGrpcPAPClient creates a new gRPC client for the PAP service.
	CreateGrpcPAPClient(zapTarget string) (clients.GrpcPAPClient, error)
	// CreateGrpcPDPClient creates a new gRPC client for the PDP service.
	CreateGrpcPDPClient(zapTarget string) (clients.GrpcPDPClient, error)
	// LanguageFactory returns the language factory.
	LanguageFactory() (languages.LanguageFactory, error)
}

// Initializer is the cli initializer.
type Initializer interface {
	// Info returns the infos of the commands.
	Info() Info
	//  CliCommands returns the commands.
	CliCommands(deps DependenciesProvider, v *viper.Viper) ([]*cobra.Command, error)
	// LanguageFactory returns the language factory.
	LanguageFactory() (languages.LanguageFactory, error)
}
