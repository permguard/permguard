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
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azmodelaap "github.com/permguard/permguard/pkg/transport/models/aap"
)

const (
	// commandNameForApplicationsCreate is the command name for applications create.
	commandNameForApplicationsDelete = "applications.delete"
)

// runECommandForDeleteApplication runs the command for creating an application.
func runECommandForDeleteApplication(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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
	applicationID := v.GetInt64(azoptions.FlagName(commandNameForApplicationsDelete, aziclicommon.FlagCommonApplicationID))
	application, err := client.DeleteApplication(applicationID)
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed to delete the application.")
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
		output["applications"] = []*azmodelaap.Application{application}
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForApplicationDelete creates a command for managing applicationdelete.
func createCommandForApplicationDelete(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a remote application",
		Long: aziclicommon.BuildCliLongTemplate(`This command deletes a remote application.

Examples:
  # delete an application and output the result in json format
  permguard applications delete --appid 268786704340 --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteApplication(deps, cmd, v)
		},
	}
	command.Flags().Int64(aziclicommon.FlagCommonApplicationID, 0, "specify the unique application id")
	v.BindPFlag(azoptions.FlagName(commandNameForApplicationsDelete, aziclicommon.FlagCommonApplicationID), command.Flags().Lookup(aziclicommon.FlagCommonApplicationID))
	return command
}
