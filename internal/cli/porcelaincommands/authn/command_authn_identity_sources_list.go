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

package authn

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// commandNameForIdentitySourcesList is the command name for identity sources list.
	commandNameForIdentitySourcesList = "identitysources.list"
)

// runECommandForListIdentitySources runs the command for creating an identity source.
func runECommandForListIdentitySources(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list identity sources.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "failed to list identity sources", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list identity sources.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "failed to list identity sources", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	page := v.GetInt32(azoptions.FlagName(commandNameForIdentitySourcesList, aziclicommon.FlagCommonPage))
	pageSize := v.GetInt32(azoptions.FlagName(commandNameForIdentitySourcesList, aziclicommon.FlagCommonPageSize))
	zoneID := v.GetInt64(azoptions.FlagName(commandNameForIdentitySource, aziclicommon.FlagCommonZoneID))
	identitySourceID := v.GetString(azoptions.FlagName(commandNameForIdentitySourcesList, flagIdentitySourceID))
	name := v.GetString(azoptions.FlagName(commandNameForIdentitySourcesList, aziclicommon.FlagCommonName))
	identitySources, err := client.FetchIdentitySourcesBy(page, pageSize, zoneID, identitySourceID, name)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list identity sources.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "failed to list identity sources", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, identitySource := range identitySources {
			identitySourceID := identitySource.IdentitySourceID
			identitySourceName := identitySource.Name
			output[identitySourceID] = identitySourceName
		}
	} else if ctx.IsJSONOutput() {
		output["identity_sources"] = identitySources
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForIdentitySourceList creates a command for managing identity sources list.
func createCommandForIdentitySourceList(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote identity sources",
		Long: aziclicommon.BuildCliLongTemplate(`This command lists all remote identity sources.

Examples:
  # list all identity sources and output in json format
  permguard authn identitysources list --zoneid 273165098782 --output json
  # list all identity sources and filter by name
  permguard authn identitysources list --zoneid 273165098782 --name google
  # list all identity sources and filter by identity source id
  permguard authn identitysources list --zoneid 273165098782 --identitysourceid 1da1d9094501425085859c60429163c2
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListIdentitySources(deps, cmd, v)
		},
	}
	command.Flags().Int32P(aziclicommon.FlagCommonPage, aziclicommon.FlagCommonPageShort, 1, "specify the page number for paginated results")
	v.BindPFlag(azoptions.FlagName(commandNameForIdentitySourcesList, aziclicommon.FlagCommonPage), command.Flags().Lookup(aziclicommon.FlagCommonPage))
	command.Flags().Int32P(aziclicommon.FlagCommonPageSize, aziclicommon.FlagCommonPageSizeShort, 1000, "specify the number of results per page")
	v.BindPFlag(azoptions.FlagName(commandNameForIdentitySourcesList, aziclicommon.FlagCommonPageSize), command.Flags().Lookup(aziclicommon.FlagCommonPageSize))
	command.Flags().String(flagIdentitySourceID, "", "filter results by identity source id")
	v.BindPFlag(azoptions.FlagName(commandNameForIdentitySourcesList, flagIdentitySourceID), command.Flags().Lookup(flagIdentitySourceID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "filter results by identity source name")
	v.BindPFlag(azoptions.FlagName(commandNameForIdentitySourcesList, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
