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
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

const (
	// commandNameForZonesCreate is the command name for zones create.
	commandNameForZonesDelete = "zones-delete"
)

// runECommandForDeleteZone runs the command for creating a zone.
func runECommandForDeleteZone(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapEndpoint, err := ctx.ZAPEndpoint()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to delete the zone.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to delete the zone"), err))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapEndpoint)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to delete the zone.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to delete the zone"), err))
		}
		return common.ErrCommandSilent
	}
	zoneID := v.GetInt64(options.FlagName(commandNameForZonesDelete, common.FlagCommonZoneID))
	zone, err := client.DeleteZone(zoneID)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to delete the zone.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to delete the zone"), err))
		}
		return common.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		zoneID := strconv.FormatInt(zone.ZoneID, 10)
		output[zoneID] = zone.Name
	} else if ctx.IsJSONOutput() {
		output["zones"] = []*zap.Zone{zone}
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForZoneDelete creates a command for managing zonedelete.
func createCommandForZoneDelete(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a remote zone",
		Long: common.BuildCliLongTemplate(`This command deletes a remote zone.

Examples:
  # delete a zone and output the result in json format
  permguard zones delete --zone-id 273165098782 --output json
		`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForDeleteZone(deps, cmd, v)
		},
	}
	command.Flags().Int64(common.FlagCommonZoneID, 0, "specify the ID of the zone to delete")
	_ = v.BindPFlag(options.FlagName(commandNameForZonesDelete, common.FlagCommonZoneID), command.Flags().Lookup(common.FlagCommonZoneID))
	return command
}
