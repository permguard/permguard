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
	commandNameForIdentitySource = "identitysource"
	flagIdentitySourceID         = "identitysourceid"
)

// runECommandForCreateIdentitySource runs the command for creating an identity source.
func runECommandForUpsertIdentitySource(cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	ctx, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red(errorMessageInvalidInputs)
		return ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := aziclients.NewGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return ErrCommandSilent
	}
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForIdentitySource, flagCommonAccountID))
	name := v.GetString(azconfigs.FlagName(flagPrefix, flagCommonName))
	identitySource := &azmodels.IdentitySource{
		AccountID: accountID,
		Name:      name,
	}
	if isCreate {
		identitySource, err = client.CreateIdentitySource(accountID, name)
	} else {
		identitySourceID := v.GetString(azconfigs.FlagName(flagPrefix, flagIdentitySourceID))
		identitySource.IdentitySourceID = identitySourceID
		identitySource, err = client.UpdateIdentitySource(identitySource)
	}
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		identitySourceID := identitySource.IdentitySourceID
		identitieSourceName := identitySource.Name
		output[identitySourceID] = identitieSourceName
	} else if ctx.IsJSONOutput() {
		output["identity_sources"] = []*azmodels.IdentitySource{identitySource}
	}
	printer.Print(output)
	return nil
}

// runECommandForIdentitySources runs the command for managing identity sources.
func runECommandForIdentitySources(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForIdentitySources creates a command for managing identity sources.
func createCommandForIdentitySources(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "identitysources",
		Short: "Manage Identity Sources",
		Long:  `This command manages identity sources.`,
		RunE:  runECommandForIdentitySources,
	}

	command.PersistentFlags().Int64(flagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitySource, flagCommonAccountID), command.PersistentFlags().Lookup(flagCommonAccountID))

	command.AddCommand(createCommandForIdentitySourceCreate(v))
	command.AddCommand(createCommandForIdentitySourceUpdate(v))
	command.AddCommand(createCommandForIdentitySourceDelete(v))
	command.AddCommand(createCommandForIdentitySourceList(v))
	return command
}
