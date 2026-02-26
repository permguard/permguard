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
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

// runECommandForUpsertZone runs the command for creating or updating a zone.
func runECommandForUpsertZone(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	opGetErroMessage := func(op bool) string {
		if op {
			return "Failed to create the zone"
		}
		return "Failed to upsert the zone"
	}
	if deps == nil {
		color.Red("cli: an issue has been detected with the cli code configuration. please create a github issue with the details")
		return common.ErrCommandSilent
	}
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapTarget, err := ctx.ZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(fmt.Errorf("cli: %s", strings.ToLower(opGetErroMessage(isCreate))), err))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(fmt.Errorf("cli: %s", strings.ToLower(opGetErroMessage(isCreate))), err))
		}
		return common.ErrCommandSilent
	}
	name := v.GetString(options.FlagName(flagPrefix, common.FlagCommonName))
	var zone *zap.Zone
	if isCreate {
		zone, err = client.CreateZone(name)
	} else {
		zoneID := v.GetInt64(options.FlagName(flagPrefix, common.FlagCommonZoneID))
		inputZone := &zap.Zone{
			ZoneID: zoneID,
			Name:   name,
		}
		zone, err = client.UpdateZone(inputZone)
	}
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(fmt.Errorf("cli: %s", strings.ToLower(opGetErroMessage(isCreate))), err))
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

// runECommandForZones runs the command for managing zones.
func runECommandForZones(cmd *cobra.Command, _ []string) error {
	return cmd.Help()
}

// CreateCommandForZones creates a command for managing zones.
func CreateCommandForZones(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "zones",
		Short: "Manage zones on the remote server",
		Long:  common.BuildCliLongTemplate(`This command manages zones on the remote server.`),
		RunE:  runECommandForZones,
	}

	command.PersistentFlags().Int64(common.FlagCommonZoneID, 0, "filter results by zone ID across all subcommands")
	_ = v.BindPFlag(options.FlagName(commandNameForZonesList, common.FlagCommonZoneID), command.Flags().Lookup(common.FlagCommonZoneID))

	command.AddCommand(createCommandForZoneCreate(deps, v))
	command.AddCommand(createCommandForZoneUpdate(deps, v))
	command.AddCommand(createCommandForZoneDelete(deps, v))
	command.AddCommand(createCommandForZoneList(deps, v))
	return command
}
