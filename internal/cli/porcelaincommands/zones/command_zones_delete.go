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
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelzap "github.com/permguard/permguard/pkg/transport/models/zap"
)

const (
	// commandNameForZonesCreate is the command name for zones create.
	commandNameForZonesDelete = "zones.delete"
)

// runECommandForDeleteZone runs the command for creating a zone.
func runECommandForDeleteZone(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		printer.Println("Failed to delete the zone.")
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "failed to delete the zone", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		printer.Println("Failed to delete the zone.")
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "failed to delete the zone", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	zoneID := v.GetInt64(azoptions.FlagName(commandNameForZonesDelete, aziclicommon.FlagCommonZoneID))
	zone, err := client.DeleteZone(zoneID)
	if err != nil {
		printer.Println("Failed to delete the zone.")
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliOperation, "failed to delete the zone", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		zoneID := fmt.Sprintf("%d", zone.ZoneID)
		output[zoneID] = zone.Name
	} else if ctx.IsJSONOutput() {
		output["zones"] = []*azmodelzap.Zone{zone}
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForZoneDelete creates a command for managing zonedelete.
func createCommandForZoneDelete(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a remote zone",
		Long: aziclicommon.BuildCliLongTemplate(`This command deletes a remote zone.

Examples:
  # delete a zone and output the result in json format
  permguard zones delete --zoneid 268786704340 --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteZone(deps, cmd, v)
		},
	}
	command.Flags().Int64(aziclicommon.FlagCommonZoneID, 0, "specify the unique zone id")
	v.BindPFlag(azoptions.FlagName(commandNameForZonesDelete, aziclicommon.FlagCommonZoneID), command.Flags().Lookup(aziclicommon.FlagCommonZoneID))
	return command
}
