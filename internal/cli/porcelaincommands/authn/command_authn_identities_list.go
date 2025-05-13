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
	// commandNameForIdentitiesList is the command name for identities list.
	commandNameForIdentitiesList = "identities-list"
)

// runECommandForListIdentities runs the command for creating an identity.
func runECommandForListIdentities(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list identities.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list identities")))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list identities.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list identities")))
		}
		return common.ErrCommandSilent
	}
	page := v.GetInt32(options.FlagName(commandNameForIdentitiesList, common.FlagCommonPage))
	pageSize := v.GetInt32(options.FlagName(commandNameForIdentitiesList, common.FlagCommonPageSize))
	zoneID := v.GetInt64(options.FlagName(commandNameForIdentity, common.FlagCommonZoneID))
	identitySourceID := v.GetString(options.FlagName(commandNameForIdentitiesList, flagIdentitySourceID))
	identityID := v.GetString(options.FlagName(commandNameForIdentitiesList, flagIdentityID))
	kind := v.GetString(options.FlagName(commandNameForIdentitiesList, flagIdentityKind))
	name := v.GetString(options.FlagName(commandNameForIdentitiesList, common.FlagCommonName))
	identities, err := client.FetchIdentitiesBy(page, pageSize, zoneID, identitySourceID, identityID, kind, name)
	if err != nil {
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list identities")))
		}
		return common.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, identity := range identities {
			identityID := identity.IdentityID
			identityName := identity.Name
			output[identityID] = identityName
		}
	} else if ctx.IsJSONOutput() {
		output["identities"] = identities
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForIdentityList creates a command for managing identitylist.
func createCommandForIdentityList(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote identities",
		Long: common.BuildCliLongTemplate(`This command lists all remote identities.

Examples:
  # list all identities and output the result in json format
  permguard authn identities list --zone-id 273165098782 --output json
  # list all identities and apply filter by name
  permguard authn identities list --zone-id 273165098782 --name branch
  # list all identities and apply filter by identity source id
  permguard authn identities list --zone-id 273165098782 --identity-id 1da1d9094501425085859c60429163c2
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListIdentities(deps, cmd, v)
		},
	}

	command.Flags().Int32P(common.FlagCommonPage, common.FlagCommonPageShort, 1, "specify the page number for paginated results")
	v.BindPFlag(options.FlagName(commandNameForIdentitiesList, common.FlagCommonPage), command.Flags().Lookup(common.FlagCommonPage))

	command.Flags().Int32P(common.FlagCommonPageSize, common.FlagCommonPageSizeShort, 1000, "specify the number of results per page")
	v.BindPFlag(options.FlagName(commandNameForIdentitiesList, common.FlagCommonPageSize), command.Flags().Lookup(common.FlagCommonPageSize))

	command.Flags().String(flagIdentitySourceID, "", "filter results by identity source id")
	v.BindPFlag(options.FlagName(commandNameForIdentitiesList, flagIdentitySourceID), command.Flags().Lookup(flagIdentitySourceID))

	command.Flags().String(flagIdentityID, "", "filter results by identity id")
	v.BindPFlag(options.FlagName(commandNameForIdentitiesList, flagIdentityID), command.Flags().Lookup(flagIdentityID))

	command.Flags().String(common.FlagCommonName, "", "filter results by identity name")
	v.BindPFlag(options.FlagName(commandNameForIdentitiesList, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
