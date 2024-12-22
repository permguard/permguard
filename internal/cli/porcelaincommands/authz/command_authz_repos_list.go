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

package authz

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
	// commandNameForRepositoriesList is the command name for repositories list.
	commandNameForRepositoriesList = "repositories.list"
)

// runECommandForListRepositories runs the command for creating a repository.
func runECommandForListRepositories(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	papTarget := ctx.GetPAPTarget()
	client, err := deps.CreateGrpcPAPClient(papTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid pap target %s", papTarget))
		return aziclicommon.ErrCommandSilent
	}
	page := v.GetInt32(azoptions.FlagName(commandNameForRepositoriesList, aziclicommon.FlagCommonPage))
	pageSize := v.GetInt32(azoptions.FlagName(commandNameForRepositoriesList, aziclicommon.FlagCommonPageSize))
	accountID := v.GetInt64(azoptions.FlagName(commandNameForRepository, aziclicommon.FlagCommonAccountID))
	repositoryID := v.GetString(azoptions.FlagName(commandNameForRepositoriesList, flagRepositoryID))
	name := v.GetString(azoptions.FlagName(commandNameForRepositoriesList, aziclicommon.FlagCommonName))
	repositories, err := client.FetchRepositoriesBy(page, pageSize, accountID, repositoryID, name)
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed to list repositories.")
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, repository := range repositories {
			repositoryID := repository.RepositoryID
			repositoryName := repository.Name
			output[repositoryID] = repositoryName
		}
	} else if ctx.IsJSONOutput() {
		output["repositories"] = repositories
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForRepositoryList creates a command for managing repositorylist.
func createCommandForRepositoryList(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote repositories",
		Long: aziclicommon.BuildCliLongTemplate(`This command lists all remote repositories.

Examples:
  # list all repositories and output in json format
  permguard authz repos list --account 268786704340 --output json
  # list all repositories filtered by name
  permguard authz repos list --account 268786704340 --name v1
  # list all repositories filtered by repository id
  permguard authz repos list --account 268786704340 --repositoryid 668f3771eacf4094ba8a80942ea5fd3f
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListRepositories(deps, cmd, v)
		},
	}
	command.Flags().Int32P(aziclicommon.FlagCommonPage, aziclicommon.FlagCommonPageShort, 1, "specify the page number for paginated results")
	v.BindPFlag(azoptions.FlagName(commandNameForRepositoriesList, aziclicommon.FlagCommonPage), command.Flags().Lookup(aziclicommon.FlagCommonPage))
	command.Flags().Int32P(aziclicommon.FlagCommonPageSize, aziclicommon.FlagCommonPageSizeShort, 1000, "specify the number of results per page")
	v.BindPFlag(azoptions.FlagName(commandNameForRepositoriesList, aziclicommon.FlagCommonPageSize), command.Flags().Lookup(aziclicommon.FlagCommonPageSize))
	command.Flags().String(flagRepositoryID, "", "filter results by repository id")
	v.BindPFlag(azoptions.FlagName(commandNameForRepositoriesList, flagRepositoryID), command.Flags().Lookup(flagRepositoryID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "filter results by repository name")
	v.BindPFlag(azoptions.FlagName(commandNameForRepositoriesList, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
