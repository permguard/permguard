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

package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclients "github.com/permguard/permguard/internal/agents/clients"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForIdentitiesList = "identities.list"
)

// runECommandForListIdentities runs the command for creating an identity.
func runECommandForListIdentities(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := createContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(errorMessageCliBug)
		return ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := aziclients.NewGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return ErrCommandSilent
	}
	page := v.GetInt32(azconfigs.FlagName(commandNameForIdentitiesList, flagCommonPage))
	pageSize := v.GetInt32(azconfigs.FlagName(commandNameForIdentitiesList, flagCommonPageSize))
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForIdentity, flagCommonAccountID))
	identitySourceID := v.GetString(azconfigs.FlagName(commandNameForIdentitiesList, flagIdentitySourceID))
	identityID := v.GetString(azconfigs.FlagName(commandNameForIdentitiesList, flagIdentityID))
	kind := v.GetString(azconfigs.FlagName(commandNameForIdentitiesList, flagIdentityKind))
	name := v.GetString(azconfigs.FlagName(commandNameForIdentitiesList, flagCommonName))
	identities, err := client.FetchIdentitiesBy(page, pageSize, accountID, identitySourceID, identityID, kind, name)
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
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
	printer.Print(output)
	return nil
}

// createCommandForIdentityList creates a command for managing identitylist.
func createCommandForIdentityList(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List identities",
		Long: fmt.Sprintf(cliLongTemplate, `This command lists all the identities.

Examples:
  # list all identities for account 301990992055
  permguard authn identities list --account 301990992055
  # list all identities for account 301990992055 and filter by name identity1
  permguard authn identities list --account 301990992055 --name identity1
  # list all identities for account 301990992055 and filter by identity id 377532e1-befe-47cb-a55a-0a789c5ec8fd
  permguard authn identities list --account 301990992055 --identityid 377532e1-befe-47cb-a55a-0a789c5ec8fd
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListIdentities(deps, cmd, v)
		},
	}
	command.Flags().Int32P(flagCommonPage, flagCommonPageShort, 1, "page number")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesList, flagCommonPage), command.Flags().Lookup(flagCommonPage))
	command.Flags().Int32P(flagCommonPageSize, flagCommonPageSizeShort, 1000, "page size")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesList, flagCommonPageSize), command.Flags().Lookup(flagCommonPageSize))
	command.Flags().String(flagIdentitySourceID, "", "identity source id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesList, flagIdentitySourceID), command.Flags().Lookup(flagIdentitySourceID))
	command.Flags().String(flagIdentityKind, "", "identity kind filer")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesList, flagIdentityKind), command.Flags().Lookup(flagIdentityKind))
	command.Flags().String(flagIdentityID, "", "identity id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesList, flagIdentityID), command.Flags().Lookup(flagIdentityID))
	command.Flags().String(flagCommonName, "", "identity name filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesList, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
