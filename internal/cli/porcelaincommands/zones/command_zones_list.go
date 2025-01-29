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
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForZonesList is the command name for zones list.
	commandNameForZonesList = "zones.list"
)

// runECommandForListZones runs the command for creating a zone.
func runECommandForListZones(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		printer.Error(fmt.Errorf("invalid zap target %s", zapTarget))
		return aziclicommon.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid zap target %s", zapTarget))
		return aziclicommon.ErrCommandSilent
	}

	page := v.GetInt32(azoptions.FlagName(commandNameForZonesList, aziclicommon.FlagCommonPage))
	pageSize := v.GetInt32(azoptions.FlagName(commandNameForZonesList, aziclicommon.FlagCommonPageSize))
	zoneID := v.GetInt64(azoptions.FlagName(commandNameForZonesList, aziclicommon.FlagCommonZoneID))
	name := v.GetString(azoptions.FlagName(commandNameForZonesList, aziclicommon.FlagCommonName))

	zones, err := client.FetchZonesBy(page, pageSize, zoneID, name)
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed list the zones.")
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, zone := range zones {
			zoneID := fmt.Sprintf("%d", zone.ZoneID)
			output[zoneID] = zone.Name
		}
	} else if ctx.IsJSONOutput() {
		output["zones"] = zones
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForZoneList creates a command for managing zonelist.
func createCommandForZoneList(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote zones",
		Long: aziclicommon.BuildCliLongTemplate(`This command lists all remote zones.

Examples:
  # list all zones and output the result in json format
  permguard zones list --output json
  # list all zones for page 1 and page size 100
  permguard zones list --page 1 --size 100
  # list zones and filter by zone
  permguard zones list --zoneid 301
  # list zones and filter by zone and name
  permguard zones list --zoneid 301--name dev
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListZones(deps, cmd, v)
		},
	}
	command.Flags().Int32P(aziclicommon.FlagCommonPage, aziclicommon.FlagCommonPageShort, 1, "specify the page number for pagination")
	v.BindPFlag(azoptions.FlagName(commandNameForZonesList, aziclicommon.FlagCommonPage), command.Flags().Lookup(aziclicommon.FlagCommonPage))
	command.Flags().Int32P(aziclicommon.FlagCommonPageSize, aziclicommon.FlagCommonPageSizeShort, 1000, "specify the number of items per page")
	v.BindPFlag(azoptions.FlagName(commandNameForZonesList, aziclicommon.FlagCommonPageSize), command.Flags().Lookup(aziclicommon.FlagCommonPageSize))
	command.Flags().Int64(aziclicommon.FlagCommonZoneID, 0, "filter results by zone ID")
	v.BindPFlag(azoptions.FlagName(commandNameForZonesList, aziclicommon.FlagCommonZoneID), command.Flags().Lookup(aziclicommon.FlagCommonZoneID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "filter results by zone name")
	v.BindPFlag(azoptions.FlagName(commandNameForZonesList, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
