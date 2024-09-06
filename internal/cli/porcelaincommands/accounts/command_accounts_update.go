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

package accounts

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForAccountsUpdate is the command name for accounts update.
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
		Short: "Update a remote account",
		Long: aziclicommon.BuildCliLongTemplate(`This command updates a remote account.

Examples:
  # update an account and output the result in json format
  permguard accounts update --account 268786704340 --name magicfarmacia-dev --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateAccount(deps, cmd, v)
		},
	}
	command.Flags().Int64(aziclicommon.FlagCommonAccountID, 0, "account id")
	v.BindPFlag(azoptions.FlagName(commandNameForAccountsUpdate, aziclicommon.FlagCommonAccountID), command.Flags().Lookup(aziclicommon.FlagCommonAccountID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "account name")
	v.BindPFlag(azoptions.FlagName(commandNameForAccountsUpdate, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
