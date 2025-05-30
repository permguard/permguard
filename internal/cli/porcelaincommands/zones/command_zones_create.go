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

package zones

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForZonesCreate is the command name for zones create.
	commandNameForZonesCreate = "zones-create"
)

// runECommandForCreateZone runs the command for creating a zone.
func runECommandForCreateZone(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertZone(deps, cmd, v, commandNameForZonesCreate, true)
}

// createCommandForZoneCreate creates a command for managing zonecreate.
func createCommandForZoneCreate(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a remote zone",
		Long: common.BuildCliLongTemplate(`This command creates a remote zone.

Examples:
  # create a zone and output the result in json format
  permguard zones create --name magicfarmacia-dev --output json`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCreateZone(deps, cmd, v)
		},
	}
	command.Flags().String(common.FlagCommonName, "", "specify the zone name")
	v.BindPFlag(options.FlagName(commandNameForZonesCreate, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
