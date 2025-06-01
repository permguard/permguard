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
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForIdentitySourcesList is the command name for identity sources list.
	commandNameForIdentitySourcesList = "identitysources-list"
)

// runECommandForListIdentitySources runs the command for creating an identity source.
func runECommandForListIdentitySources(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapTarget, err := ctx.ZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list identity sources.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list identity sources")))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list identity sources.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list identity sources")))
		}
		return common.ErrCommandSilent
	}
	page := v.GetInt32(options.FlagName(commandNameForIdentitySourcesList, common.FlagCommonPage))
	pageSize := v.GetInt32(options.FlagName(commandNameForIdentitySourcesList, common.FlagCommonPageSize))
	zoneID := v.GetInt64(options.FlagName(commandNameForIdentitySource, common.FlagCommonZoneID))
	identitySourceID := v.GetString(options.FlagName(commandNameForIdentitySourcesList, flagIdentitySourceID))
	name := v.GetString(options.FlagName(commandNameForIdentitySourcesList, common.FlagCommonName))
	identitySources, err := client.FetchIdentitySourcesBy(page, pageSize, zoneID, identitySourceID, name)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list identity sources.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list identity sources")))
		}
		return common.ErrCommandSilent
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
func createCommandForIdentitySourceList(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote identity sources",
		Long: common.BuildCliLongTemplate(`This command lists all remote identity sources.

Examples:
  # list all identity sources and output in json format
  permguard authn identitysources list --zone-id 273165098782 --output json
  # list all identity sources and filter by name
  permguard authn identitysources list --zone-id 273165098782 --name google
  # list all identity sources and filter by identity source id
  permguard authn identitysources list --zone-id 273165098782 --identitysource-id 1da1d9094501425085859c60429163c2
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListIdentitySources(deps, cmd, v)
		},
	}
	command.Flags().Int32P(common.FlagCommonPage, common.FlagCommonPageShort, 1, "specify the page number for paginated results")
	v.BindPFlag(options.FlagName(commandNameForIdentitySourcesList, common.FlagCommonPage), command.Flags().Lookup(common.FlagCommonPage))
	command.Flags().Int32P(common.FlagCommonPageSize, common.FlagCommonPageSizeShort, 1000, "specify the number of results per page")
	v.BindPFlag(options.FlagName(commandNameForIdentitySourcesList, common.FlagCommonPageSize), command.Flags().Lookup(common.FlagCommonPageSize))
	command.Flags().String(flagIdentitySourceID, "", "filter results by identity source id")
	v.BindPFlag(options.FlagName(commandNameForIdentitySourcesList, flagIdentitySourceID), command.Flags().Lookup(flagIdentitySourceID))
	command.Flags().String(common.FlagCommonName, "", "filter results by identity source name")
	v.BindPFlag(options.FlagName(commandNameForIdentitySourcesList, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
