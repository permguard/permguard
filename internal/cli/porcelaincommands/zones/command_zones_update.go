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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForZonesUpdate is the command name for zones update.
	commandNameForZonesUpdate = "zones.update"
)

// runECommandForUpdateZone runs the command for creating a zone.
func runECommandForUpdateZone(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertZone(deps, cmd, v, commandNameForZonesUpdate, false)
}

// createCommandForZoneUpdate creates a command for managing zoneupdate.
func createCommandForZoneUpdate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update a remote zone",
		Long: aziclicommon.BuildCliLongTemplate(`This command updates a remote zone.

Examples:
  # update a zone and output the result in json format
  permguard zones update --zoneid 268786704340 --name magicfarmacia-dev --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateZone(deps, cmd, v)
		},
	}
	command.Flags().Int64(aziclicommon.FlagCommonZoneID, 0, "specify the zone id to update")
	v.BindPFlag(azoptions.FlagName(commandNameForZonesUpdate, aziclicommon.FlagCommonZoneID), command.Flags().Lookup(aziclicommon.FlagCommonZoneID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "specify the new zone name")
	v.BindPFlag(azoptions.FlagName(commandNameForZonesUpdate, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
