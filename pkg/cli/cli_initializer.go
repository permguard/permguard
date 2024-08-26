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
)

// CliDependenciesProvider is the cli dependencies provider.
type CliDependenciesProvider interface {
	// CreateContext creates a new context.
	CreateContext(cmd *cobra.Command, v *viper.Viper) (CliContext, error)
	// CreatePrinter creates a new printer.
	CreatePrinter(ctx CliContext, cmd *cobra.Command, v *viper.Viper) (*CliPrinter, error)
	// CreateContextAndPrinter creates a new context and printer.
	CreateContextAndPrinter(cmd *cobra.Command, v *viper.Viper) (CliContext, *CliPrinter, error)
}

// CliInitializer is the cli initializer.
type CliInitializer interface {
	// GetCliInfo returns the infos of the commands.
	GetCliInfo() CliInfo
	//  GetCliCommands returns the commands.
	GetCliCommands(deps CliDependenciesProvider, v *viper.Viper) ([]*cobra.Command, error)
}
