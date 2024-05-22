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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForRepositoriesCreate = "repositories.create"
)

// runECommandForCreateRepository runs the command for creating a repository.
func runECommandForCreateRepository(cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertRepository(cmd, v, commandNameForRepositoriesCreate, true)
}

// createCommandForRepositoryCreate creates a command for managing repositorycreate.
func createCommandForRepositoryCreate(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a repository",
		Long: `This command create a repository.

Examples:
  # create a repository with name repository1 and account 301990992055
  permguard authn repositories create --account 301990992055 --name repository1
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCreateRepository(cmd, v)
		},
	}
	command.Flags().String(flagCommonName, "", "repository name")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepositoriesCreate, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
