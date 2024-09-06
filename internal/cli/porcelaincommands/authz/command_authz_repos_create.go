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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/cli/configs"
)

const (
	// commandNameForRepositoriesCreate is the command name for repositories create.
	commandNameForRepositoriesCreate = "repositories.create"
)

// runECommandForCreateRepository runs the command for creating a repository.
func runECommandForCreateRepository(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertRepository(deps, cmd, v, commandNameForRepositoriesCreate, true)
}

// createCommandForRepositoryCreate creates a command for managing repositorycreate.
func createCommandForRepositoryCreate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a remote repository",
		Long: aziclicommon.BuildCliLongTemplate(`This command creates a remote repository.

Examples:
  # create a repository and output the result in json format
  permguard authz repos create --account 268786704340 --name v2.0 --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCreateRepository(deps, cmd, v)
		},
	}
	command.Flags().String(aziclicommon.FlagCommonName, "", "repository name")
	v.BindPFlag(azconfigs.FlagName(commandNameForRepositoriesCreate, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
