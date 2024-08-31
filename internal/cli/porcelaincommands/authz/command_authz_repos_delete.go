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
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	// commandNameForRepository is the command name for repository.
	commandNameForRepositoriesDelete = "repositories.delete"
)

// runECommandForDeleteRepository runs the command for creating a repository.
func runECommandForDeleteRepository(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForRepository, aziclicommon.FlagCommonAccountID))
	repositoryID := v.GetString(azconfigs.FlagName(commandNameForRepositoriesDelete, flagRepositoryID))
	repository, err := client.DeleteRepository(accountID, repositoryID)
	if err != nil {
		printer.Error(err)
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		repositoryID := repository.RepositoryID
		repositoryName := repository.Name
		output[repositoryID] = repositoryName
	} else if ctx.IsJSONOutput() {
		output["repositories"] = []*azmodels.Repository{repository}
	}
	printer.Print(output)
	return nil
}

// createCommandForRepositoryDelete creates a command for managing repositorydelete.
func createCommandForRepositoryDelete(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a remote repository",
		Long: aziclicommon.BuildCliLongTemplate(`This command deletes a remote repository.

Examples:
  # delete a repository and output the result in json format
  permguard authz repos delete --account 268786704340 --repositoryid 668f3771eacf4094ba8a80942ea5fd3f --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteRepository(deps, cmd, v)
		},
	}
	command.Flags().String(flagRepositoryID, "", "repository id")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepositoriesDelete, flagRepositoryID), command.Flags().Lookup(flagRepositoryID))
	return command
}
