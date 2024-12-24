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

package applications

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

// runECommandForUpsertApplication runs the command for creating or updating an application.
func runECommandForUpsertApplication(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	if deps == nil {
		color.Red("cli: an issue has been detected with the cli code configuration. please create a github issue with the details")
		return aziclicommon.ErrCommandSilent
	}
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
	name := v.GetString(azoptions.FlagName(flagPrefix, aziclicommon.FlagCommonName))
	var application *azmodels.Application
	if isCreate {
		application, err = client.CreateApplication(name)
	} else {
		applicationID := v.GetInt64(azoptions.FlagName(flagPrefix, aziclicommon.FlagCommonApplicationID))
		inputApplication := &azmodels.Application{
			ApplicationID: applicationID,
			Name:          name,
		}
		application, err = client.UpdateApplication(inputApplication)
	}
	if err != nil {
		if ctx.IsTerminalOutput() {
			if isCreate {
				printer.Println("Failed to create the application.")
			} else {
				printer.Println("Failed to update the application.")
			}
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		applicationID := fmt.Sprintf("%d", application.ApplicationID)
		output[applicationID] = application.Name
	} else if ctx.IsJSONOutput() {
		output["applications"] = []*azmodels.Application{application}
	}
	printer.PrintlnMap(output)
	return nil
}

// runECommandForApplications runs the command for managing applications.
func runECommandForApplications(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// CreateCommandForApplications creates a command for managing applications.
func CreateCommandForApplications(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "apps",
		Short: "Manage applications on the remote server",
		Long:  aziclicommon.BuildCliLongTemplate(`This command manages applications on the remote server.`),
		RunE:  runECommandForApplications,
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonApplicationID, 0, "filter results by application ID across all subcommands")
	v.BindPFlag(azoptions.FlagName(commandNameForApplicationsList, aziclicommon.FlagCommonApplicationID), command.Flags().Lookup(aziclicommon.FlagCommonApplicationID))

	command.AddCommand(createCommandForApplicationCreate(deps, v))
	command.AddCommand(createCommandForApplicationUpdate(deps, v))
	command.AddCommand(createCommandForApplicationDelete(deps, v))
	command.AddCommand(createCommandForApplicationList(deps, v))
	return command
}
