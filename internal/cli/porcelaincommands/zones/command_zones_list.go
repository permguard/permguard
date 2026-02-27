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
	"errors"
	"fmt"
	"strconv"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForZonesList is the command name for zones list.
	commandNameForZonesList = "zones-list"
)

// runECommandForListZones runs the command for creating a zone.
func runECommandForListZones(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapEndpoint, err := ctx.ZAPEndpoint()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list zones.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to list zones"), err))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapEndpoint)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list zones.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to list zones"), err))
		}
		return common.ErrCommandSilent
	}

	page := v.GetInt32(options.FlagName(commandNameForZonesList, common.FlagCommonPage))
	pageSize := v.GetInt32(options.FlagName(commandNameForZonesList, common.FlagCommonPageSize))
	zoneID := v.GetInt64(options.FlagName(commandNameForZonesList, common.FlagCommonZoneID))
	name := v.GetString(options.FlagName(commandNameForZonesList, common.FlagCommonName))

	zones, err := client.FetchZonesBy(page, pageSize, zoneID, name)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list zones.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to list zones"), err))
		}
		return common.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, zone := range zones {
			zoneID := strconv.FormatInt(zone.ZoneID, 10)
			output[zoneID] = zone.Name
		}
	} else if ctx.IsJSONOutput() {
		output["zones"] = zones
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForZoneList creates a command for managing zonelist.
func createCommandForZoneList(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote zones",
		Long: common.BuildCliLongTemplate(`This command lists all remote zones.

Examples:
  # list all zones and output the result in json format
  permguard zones list --output json
  # list all zones for page 1 and page size 100
  permguard zones list --page 1 --size 100
  # list zones and filter by zone
  permguard zones list --zone-id 268786704340
  # list zones and filter by zone and name
  permguard zones list --zone-id 268786704340--name dev
		`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForListZones(deps, cmd, v)
		},
	}
	command.Flags().Int32P(common.FlagCommonPage, common.FlagCommonPageShort, 1, "specify the page number for pagination")
	_ = v.BindPFlag(options.FlagName(commandNameForZonesList, common.FlagCommonPage), command.Flags().Lookup(common.FlagCommonPage))
	command.Flags().Int32P(common.FlagCommonPageSize, common.FlagCommonPageSizeShort, 1000, "specify the number of items per page")
	_ = v.BindPFlag(options.FlagName(commandNameForZonesList, common.FlagCommonPageSize), command.Flags().Lookup(common.FlagCommonPageSize))
	command.Flags().Int64(common.FlagCommonZoneID, 0, "filter results by zone ID")
	_ = v.BindPFlag(options.FlagName(commandNameForZonesList, common.FlagCommonZoneID), command.Flags().Lookup(common.FlagCommonZoneID))
	command.Flags().String(common.FlagCommonName, "", "filter results by zone name")
	_ = v.BindPFlag(options.FlagName(commandNameForZonesList, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
