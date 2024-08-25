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
	commandNameForIdentitySourcesDelete = "identitysources.delete"
)

// runECommandForDeleteIdentitySource runs the command for creating an identity source.
func runECommandForDeleteIdentitySource(cmd *cobra.Command, v *viper.Viper) error {
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
	identitySourceID := v.GetString(azconfigs.FlagName(commandNameForIdentitySourcesDelete, flagIdentitySourceID))
	identitySource, err := client.DeleteIdentitySource(accountID, identitySourceID)
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		identitySourceID := identitySource.IdentitySourceID
		identitySourceName := identitySource.Name
		output[identitySourceID] = identitySourceName
	} else if ctx.IsJSONOutput() {
		output["identity_sources"] = []*azmodels.IdentitySource{identitySource}
	}
	printer.Print(output)
	return nil
}

// createCommandForIdentitySourceDelete creates a command for managing identity sources delete.
func createCommandForIdentitySourceDelete(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete an identity source",
		Long: fmt.Sprintf(cliLongTemplate, `This command deletes an identity source.

Examples:
  # delete an identity source with id 19159d69-e902-418e-966a-148c4d5169a4 and account 301990992055
  permguard authn identitysources delete --account 301990992055 --identitysourceid 19159d69-e902-418e-966a-148c4d5169a4
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteIdentitySource(cmd, v)
		},
	}
	command.Flags().String(flagIdentitySourceID, "", "identity source id")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitySourcesDelete, flagIdentitySourceID), command.Flags().Lookup(flagIdentitySourceID))
	return command
}
