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
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForIdentitySource is the command name for identity source.
	commandNameForIdentitySource = "identitysource"
	// flagIdentitySourceID is the flag for identity source id.
	flagIdentitySourceID = "identitysourceid"
)

// runECommandForCreateIdentitySource runs the command for creating an identity source.
func runECommandForUpsertIdentitySource(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := deps.CreateGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return aziclicommon.ErrCommandSilent
	}
	applicationID := v.GetInt64(azoptions.FlagName(commandNameForIdentitySource, aziclicommon.FlagCommonApplicationID))
	name := v.GetString(azoptions.FlagName(flagPrefix, aziclicommon.FlagCommonName))
	identitySource := &azmodels.IdentitySource{
		ApplicationID: applicationID,
		Name:          name,
	}
	if isCreate {
		identitySource, err = client.CreateIdentitySource(applicationID, name)
	} else {
		identitySourceID := v.GetString(azoptions.FlagName(flagPrefix, flagIdentitySourceID))
		identitySource.IdentitySourceID = identitySourceID
		identitySource, err = client.UpdateIdentitySource(identitySource)
	}
	if err != nil {
		if ctx.IsTerminalOutput() {
			if isCreate {
				printer.Println("Failed to create the identity source.")
			} else {
				printer.Println("Failed to update the identity source.")
			}
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		identitySourceID := identitySource.IdentitySourceID
		identitieSourceName := identitySource.Name
		output[identitySourceID] = identitieSourceName
	} else if ctx.IsJSONOutput() {
		output["identity_sources"] = []*azmodels.IdentitySource{identitySource}
	}
	printer.PrintlnMap(output)
	return nil
}

// runECommandForIdentitySources runs the command for managing identity sources.
func runECommandForIdentitySources(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForIdentitySources creates a command for managing identity sources.
func createCommandForIdentitySources(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "identitysources",
		Short: "Manage remote identity sources",
		Long:  aziclicommon.BuildCliLongTemplate(`This command manages remote identity sources.`),
		RunE:  runECommandForIdentitySources,
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonApplicationID, 0, "application id filter")
	v.BindPFlag(azoptions.FlagName(commandNameForIdentitySource, aziclicommon.FlagCommonApplicationID), command.PersistentFlags().Lookup(aziclicommon.FlagCommonApplicationID))

	command.AddCommand(createCommandForIdentitySourceCreate(deps, v))
	command.AddCommand(createCommandForIdentitySourceUpdate(deps, v))
	command.AddCommand(createCommandForIdentitySourceDelete(deps, v))
	command.AddCommand(createCommandForIdentitySourceList(deps, v))
	return command
}
