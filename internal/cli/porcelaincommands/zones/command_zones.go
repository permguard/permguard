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

// runECommandForUpsertZone runs the command for creating or updating a zone.
func runECommandForUpsertZone(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	opGetErroMessage := func(op bool) string {
		if op {
			return "failed to create the tenant"
		}
		return "failed to upsert the tenant"
	}
	if deps == nil {
		color.Red("cli: an issue has been detected with the cli code configuration. please create a github issue with the details")
		return aziclicommon.ErrCommandSilent
	}
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		printer.Println("Failed to upsert the zone.")
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, opGetErroMessage(isCreate), err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		printer.Println("Failed to upsert the zone.")
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, opGetErroMessage(isCreate), err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	name := v.GetString(azoptions.FlagName(flagPrefix, aziclicommon.FlagCommonName))
	var zone *azmodelzap.Zone
	if isCreate {
		zone, err = client.CreateZone(name)
	} else {
		zoneID := v.GetInt64(azoptions.FlagName(flagPrefix, aziclicommon.FlagCommonZoneID))
		inputZone := &azmodelzap.Zone{
			ZoneID: zoneID,
			Name:   name,
		}
		zone, err = client.UpdateZone(inputZone)
	}
	if err != nil {
		printer.Println("Failed to upsert the zone.")
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, opGetErroMessage(isCreate), err)
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

// runECommandForZones runs the command for managing zones.
func runECommandForZones(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// CreateCommandForZones creates a command for managing zones.
func CreateCommandForZones(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "zones",
		Short: "Manage zones on the remote server",
		Long:  aziclicommon.BuildCliLongTemplate(`This command manages zones on the remote server.`),
		RunE:  runECommandForZones,
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonZoneID, 0, "filter results by zone ID across all subcommands")
	v.BindPFlag(azoptions.FlagName(commandNameForZonesList, aziclicommon.FlagCommonZoneID), command.Flags().Lookup(aziclicommon.FlagCommonZoneID))

	command.AddCommand(createCommandForZoneCreate(deps, v))
	command.AddCommand(createCommandForZoneUpdate(deps, v))
	command.AddCommand(createCommandForZoneDelete(deps, v))
	command.AddCommand(createCommandForZoneList(deps, v))
	return command
}
