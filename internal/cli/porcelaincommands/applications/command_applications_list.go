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
)

const (
	// commandNameForApplicationsList is the command name for applications list.
	commandNameForApplicationsList = "applications.list"
)

// runECommandForListApplications runs the command for creating an application.
func runECommandForListApplications(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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

	page := v.GetInt32(azoptions.FlagName(commandNameForApplicationsList, aziclicommon.FlagCommonPage))
	pageSize := v.GetInt32(azoptions.FlagName(commandNameForApplicationsList, aziclicommon.FlagCommonPageSize))
	applicationID := v.GetInt64(azoptions.FlagName(commandNameForApplicationsList, aziclicommon.FlagCommonApplicationID))
	name := v.GetString(azoptions.FlagName(commandNameForApplicationsList, aziclicommon.FlagCommonName))

	applications, err := client.FetchApplicationsBy(page, pageSize, applicationID, name)
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed list the applications.")
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, application := range applications {
			applicationID := fmt.Sprintf("%d", application.ApplicationID)
			output[applicationID] = application.Name
		}
	} else if ctx.IsJSONOutput() {
		output["applications"] = applications
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForApplicationList creates a command for managing applicationlist.
func createCommandForApplicationList(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote applications",
		Long: aziclicommon.BuildCliLongTemplate(`This command lists all remote applications.

Examples:
  # list all applications and output the result in json format
  permguard applications list --output json
  # list all applications for page 1 and page size 100
  permguard applications list --page 1 --size 100
  # list applications and filter by application
  permguard applications list --application 301
  # list applications and filter by application and name
  permguard applications list --application 301--name dev
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListApplications(deps, cmd, v)
		},
	}
	command.Flags().Int32P(aziclicommon.FlagCommonPage, aziclicommon.FlagCommonPageShort, 1, "specify the page number for pagination")
	v.BindPFlag(azoptions.FlagName(commandNameForApplicationsList, aziclicommon.FlagCommonPage), command.Flags().Lookup(aziclicommon.FlagCommonPage))
	command.Flags().Int32P(aziclicommon.FlagCommonPageSize, aziclicommon.FlagCommonPageSizeShort, 1000, "specify the number of items per page")
	v.BindPFlag(azoptions.FlagName(commandNameForApplicationsList, aziclicommon.FlagCommonPageSize), command.Flags().Lookup(aziclicommon.FlagCommonPageSize))
	command.Flags().Int64(aziclicommon.FlagCommonApplicationID, 0, "filter results by application ID")
	v.BindPFlag(azoptions.FlagName(commandNameForApplicationsList, aziclicommon.FlagCommonApplicationID), command.Flags().Lookup(aziclicommon.FlagCommonApplicationID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "filter results by application name")
	v.BindPFlag(azoptions.FlagName(commandNameForApplicationsList, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
