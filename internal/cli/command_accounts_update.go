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
	commandNameForAccountsUpdate = "accounts.update"
)

// runECommandForUpdateAccount runs the command for creating an account.
func runECommandForUpdateAccount(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertAccount(deps, cmd, v, commandNameForAccountsUpdate, false)
}

// createCommandForAccountUpdate creates a command for managing accountupdate.
func createCommandForAccountUpdate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update an account",
		Long: fmt.Sprintf(cliLongTemplate, `This command updates an account.

Examples:
  # update the account with the account id 301990992055 and set the name to mycorporate
  permguard accounts update --account 301990992055 --name mycorporate
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateAccount(deps, cmd, v)
		},
	}
	command.Flags().Int64(flagCommonAccountID, 0, "account id")
	v.BindPFlag(azconfigs.FlagName(commandNameForAccountsUpdate, flagCommonAccountID), command.Flags().Lookup(flagCommonAccountID))
	command.Flags().String(flagCommonName, "", "account name")
	v.BindPFlag(azconfigs.FlagName(commandNameForAccountsUpdate, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
