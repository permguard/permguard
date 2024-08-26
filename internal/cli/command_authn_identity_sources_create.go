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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForIdentitySourcesCreate = "identitysources.create"
)

// runECommandForCreateIdentitySource runs the command for creating an identity source.
func runECommandForCreateIdentitySource(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertIdentitySource(deps, cmd, v, commandNameForIdentitySourcesCreate, true)
}

// createCommandForIdentitySourceCreate creates a command for managing identity sources.
func createCommandForIdentitySourceCreate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "create",
		Short: "Create an identity source",
		Long: fmt.Sprintf(cliLongTemplate, `This command creates an identity source.

Examples:
  # create an identity source with name permguard and account 301990992055
  permguard authn identitysources create --account 301990992055 --name permguard
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCreateIdentitySource(deps, cmd, v)
		},
	}
	command.Flags().String(flagCommonName, "", "identity source name")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitySourcesCreate, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
