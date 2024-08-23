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
	commandNameForRepositoriesList = "repositories.list"
)

// runECommandForListRepositories runs the command for creating a repository.
func runECommandForListRepositories(cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red(errorMessageInvalidInputs)
		return ErrCommandSilent
	}
	papTarget := ctx.GetPAPTarget()
	client, err := aziclients.NewGrpcPAPClient(papTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid pap target %s", papTarget))
		return ErrCommandSilent
	}
	page := v.GetInt32(azconfigs.FlagName(commandNameForRepositoriesList, flagCommonPage))
	pageSize := v.GetInt32(azconfigs.FlagName(commandNameForRepositoriesList, flagCommonPageSize))
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForRepository, flagCommonAccountID))
	repositoryID := v.GetString(azconfigs.FlagName(commandNameForRepositoriesList, flagRepositoryID))
	name := v.GetString(azconfigs.FlagName(commandNameForRepositoriesList, flagCommonName))
	repositories, err := client.FetchRepositoriesBy(page, pageSize, accountID, repositoryID, name)
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, repository := range repositories {
			repositoryID := repository.RepositoryID
			repositoryName := repository.Name
			output[repositoryID] = repositoryName
		}
	} else if ctx.IsJSONOutput() {
		output["repository"] = repositories
	}
	printer.Print(output)
	return nil
}

// createCommandForRepositoryList creates a command for managing repositorylist.
func createCommandForRepositoryList(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List repositories",
		Long: `This command lists all the repositories.

Examples:
  # list all repositories for account 301990992055
  permguard authz repos list --account 301990992055
  # list all repositories for account 301990992055 and filter by name repository1
  permguard authz repos list --account 301990992055 --name repository1
  # list all repositories for account 301990992055 and filter by repository id 377532e1-befe-47cb-a55a-0a789c5ec8fd
  permguard authz repos list --account 301990992055 --repositoryid 377532e1-befe-47cb-a55a-0a789c5ec8fd
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListRepositories(cmd, v)
		},
	}
	command.Flags().Int32P(flagCommonPage, flagCommonPageShort, 1, "page number")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepositoriesList, flagCommonPage), command.Flags().Lookup(flagCommonPage))
	command.Flags().Int32P(flagCommonPageSize, flagCommonPageSizeShort, 1000, "page size")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepositoriesList, flagCommonPageSize), command.Flags().Lookup(flagCommonPageSize))
	command.Flags().String(flagRepositoryID, "", "repository id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepositoriesList, flagRepositoryID), command.Flags().Lookup(flagRepositoryID))
	command.Flags().String(flagCommonName, "", "repository name filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepositoriesList, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
