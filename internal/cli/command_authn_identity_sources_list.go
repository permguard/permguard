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
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForIdentitySourcesList = "identitysources.list"
)

// runECommandForListIdentitySources runs the command for creating an identity source.
func runECommandForListIdentitySources(cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red("invalid inputs")
		return ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := aziclients.NewGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return ErrCommandSilent
	}
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForIdentitySource, flagCommonAccountID))
	identitySourceID := v.GetString(azconfigs.FlagName(commandNameForIdentitySourcesList, flagIdentitySourceID))
	name := v.GetString(azconfigs.FlagName(commandNameForIdentitySourcesList, flagCommonName))
	identitySources, err := client.GetIdentitySourcesBy(accountID, identitySourceID, name)
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
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
	printer.Print(output)
	return nil
}

// createCommandForIdentitySourceList creates a command for managing identity sources list.
func createCommandForIdentitySourceList(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List identity sources",
		Long: `This command lists all the identity sources.

Examples:
  # list all identity sources for account 301990992055
  permguard authn identitysources list --account 301990992055
  # list all identity sources for account 301990992055 and filter by name permguard
  permguard authn identitysources list --account 301990992055 --name permguard
  # list all identity sources for account 301990992055 and filter by identity source id 377532e1-befe-47cb-a55a-0a789c5ec8fd
  permguard authn identitysources list --account 301990992055 --identitysourceid 377532e1-befe-47cb-a55a-0a789c5ec8fd
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListIdentitySources(cmd, v)
		},
	}
	command.Flags().String(flagIdentitySourceID, "", "identity source id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitySourcesList, flagIdentitySourceID), command.Flags().Lookup(flagIdentitySourceID))
	command.Flags().String(flagCommonName, "", "identity source name filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitySourcesList, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
