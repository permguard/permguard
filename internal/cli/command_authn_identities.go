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
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForIdentity = "identity"
	flagIdentityID         = "identityid"
	flagIdentityKind       = "kind"
)

// runECommandForCreateIdentity runs the command for creating an identity.
func runECommandForUpsertIdentity(cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	ctx, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red("invalid inputs")
		return ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := aziclients.NewGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Sprintf("invalid aap target %s", aapTarget), err)
		return ErrCommandSilent
	}
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForIdentity, flagCommonAccountID))
	name := v.GetString(azconfigs.FlagName(flagPrefix, flagCommonName))
	kind := v.GetString(azconfigs.FlagName(flagPrefix, flagIdentityKind))
	identity := &azmodels.Identity{
		AccountID: accountID,
		Kind:      kind,
		Name:      name,
	}
	if isCreate {
		identitySourceID := v.GetString(azconfigs.FlagName(flagPrefix, flagIdentitySourceID))
		identity, err = client.CreateIdentity(accountID, identitySourceID, kind, name)
	} else {
		identityID := v.GetString(azconfigs.FlagName(flagPrefix, flagIdentityID))
		identity.IdentityID = identityID
		identity, err = client.UpdateIdentity(identity)
	}
	if err != nil {
		printer.Error("operation cannot be completed", err)
		return ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		identityID := identity.IdentityID
		identityName := identity.Name
		output[identityID] = identityName
	} else if ctx.IsJSONOutput() {
		output["identities"] = []*azmodels.Identity{identity}
	}
	printer.Print(output)
	return nil
}

// runECommandForIdentities runs the command for managing identities.
func runECommandForIdentities(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForIdentities creates a command for managing identities.
func createCommandForIdentities(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "identities",
		Short: "Manage Identities",
		Long:  `This command manages identities.`,
		RunE:  runECommandForIdentities,
	}

	command.PersistentFlags().Int64(flagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentity, flagCommonAccountID), command.PersistentFlags().Lookup(flagCommonAccountID))

	command.AddCommand(createCommandForIdentityCreate(v))
	command.AddCommand(createCommandForIdentityUpdate(v))
	command.AddCommand(createCommandForIdentityDelete(v))
	command.AddCommand(createCommandForIdentityList(v))
	return command
}
