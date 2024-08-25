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
	commandNameForRepository = "repository"
	flagRepositoryID         = "repositoryid"
)

// runECommandForCreateRepository runs the command for creating a repository.
func runECommandForUpsertRepository(cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
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
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForRepository, flagCommonAccountID))
	name := v.GetString(azconfigs.FlagName(flagPrefix, flagCommonName))
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
		return ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		repositoryID := repository.RepositoryID
		repositoryName := repository.Name
		output[repositoryID] = repositoryName
	} else if ctx.IsJSONOutput() {
		output["repository"] = []*azmodels.Repository{repository}
	}
	printer.Print(output)
	return nil
}

// runECommandForRepositories runs the command for managing repositories.
func runECommandForRepositories(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForRepositories creates a command for managing repositories.
func createCommandForRepositories(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "repos",
		Short: "Manage Repositories",
		Long:  fmt.Sprintf(cliLongTemplate, `This command manages repositories.`),
		RunE:  runECommandForRepositories,
	}

	command.PersistentFlags().Int64(flagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepository, flagCommonAccountID), command.PersistentFlags().Lookup(flagCommonAccountID))

	command.AddCommand(createCommandForRepositoryCreate(v))
	command.AddCommand(createCommandForRepositoryUpdate(v))
	command.AddCommand(createCommandForRepositoryDelete(v))
	command.AddCommand(createCommandForRepositoryList(v))
	return command
}
