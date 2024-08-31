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
	commandNameForRepository = "repository"
	// flagRepositoryID is the flag for repository id.
	flagRepositoryID = "repositoryid"
)

// runECommandForCreateRepository runs the command for creating a repository.
func runECommandForUpsertRepository(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
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
	name := v.GetString(azconfigs.FlagName(flagPrefix, aziclicommon.FlagCommonName))
	repository := &azmodels.Repository{
		AccountID: accountID,
		Name:      name,
	}
	if isCreate {
		repository, err = client.CreateRepository(accountID, name)
	} else {
		repositoryID := v.GetString(azconfigs.FlagName(flagPrefix, flagRepositoryID))
		repository.RepositoryID = repositoryID
		repository, err = client.UpdateRepository(repository)
	}
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

// runECommandForRepositories runs the command for managing repositories.
func runECommandForRepositories(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForRepositories creates a command for managing repositories.
func createCommandForRepositories(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "repos",
		Short: "Manage repositories on the remote server",
		Long:  aziclicommon.BuildCliLongTemplate(`This command manages repositories on the remote server.`),
		RunE:  runECommandForRepositories,
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepository, aziclicommon.FlagCommonAccountID), command.PersistentFlags().Lookup(aziclicommon.FlagCommonAccountID))

	command.AddCommand(createCommandForRepositoryCreate(deps, v))
	command.AddCommand(createCommandForRepositoryUpdate(deps, v))
	command.AddCommand(createCommandForRepositoryDelete(deps, v))
	command.AddCommand(createCommandForRepositoryList(deps, v))
	return command
}
