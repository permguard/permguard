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
	commandNameForRepositoriesDelete = "repositories.delete"
)

// runECommandForDeleteRepository runs the command for creating a repository.
func runECommandForDeleteRepository(cmd *cobra.Command, v *viper.Viper) error {
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
	repositoryID := v.GetString(azconfigs.FlagName(commandNameForRepositoriesDelete, flagRepositoryID))
	repository, err := client.DeleteRepository(accountID, repositoryID)
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

// createCommandForRepositoryDelete creates a command for managing repositorydelete.
func createCommandForRepositoryDelete(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a repository",
		Long: fmt.Sprintf(cliLongTemplate, `This command deletes a repository.

Examples:
  # delete a repository with id 19159d69-e902-418e-966a-148c4d5169a4 and account 301990992055
  permguard authz repos delete --account 301990992055 --repositoryid 19159d69-e902-418e-966a-148c4d5169a4
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteRepository(cmd, v)
		},
	}
	command.Flags().String(flagRepositoryID, "", "repository id")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepositoriesDelete, flagRepositoryID), command.Flags().Lookup(flagRepositoryID))
	return command
}
