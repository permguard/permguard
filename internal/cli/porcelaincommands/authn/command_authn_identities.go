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
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	// commandNameForIdentity is the command name for identity.
	commandNameForIdentity = "identity"
	// flagIdentitySourceID is the flag for identity source id.
	flagIdentityID = "identityid"
	// flagIdentitySourceID is the flag for identity source id.
	flagIdentityKind = "kind"
)

// runECommandForCreateIdentity runs the command for creating an identity.
func runECommandForUpsertIdentity(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(aziclicommon.ErrorMessageCliBug)
		return aziclicommon.ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := deps.CreateGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return aziclicommon.ErrCommandSilent
	}
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForIdentity, aziclicommon.FlagCommonAccountID))
	name := v.GetString(azconfigs.FlagName(flagPrefix, aziclicommon.FlagCommonName))
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
		printer.Error(err)
		return aziclicommon.ErrCommandSilent
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
func createCommandForIdentities(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "identities",
		Short: "Manage remote identities",
		Long:  aziclicommon.BuildCliLongTemplate(`This command manages remote identities.`),
		RunE:  runECommandForIdentities,
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentity, aziclicommon.FlagCommonAccountID), command.PersistentFlags().Lookup(aziclicommon.FlagCommonAccountID))

	command.AddCommand(createCommandForIdentityCreate(deps, v))
	command.AddCommand(createCommandForIdentityUpdate(deps, v))
	command.AddCommand(createCommandForIdentityDelete(deps, v))
	command.AddCommand(createCommandForIdentityList(deps, v))
	return command
}