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
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForAccountsCreate is the command name for accounts create.
	commandNameForAccountsDelete = "accounts.delete"
)

// runECommandForDeleteAccount runs the command for creating an account.
func runECommandForDeleteAccount(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := deps.CreateGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return aziclicommon.ErrCommandSilent
	}
	accountID := v.GetInt64(azoptions.FlagName(commandNameForAccountsDelete, aziclicommon.FlagCommonAccountID))
	account, err := client.DeleteAccount(accountID)
	if err != nil {
		if ctx.IsVerboseTerminalOutput() {
			printer.Error(err)
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		accountID := fmt.Sprintf("%d", account.AccountID)
		output[accountID] = account.Name
	} else if ctx.IsJSONOutput() {
		output["accounts"] = []*azmodels.Account{account}
	}
	printer.Print(output)
	return nil
}

// createCommandForAccountDelete creates a command for managing accountdelete.
func createCommandForAccountDelete(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a remote account",
		Long: aziclicommon.BuildCliLongTemplate(`This command deletes a remote account.

Examples:
  # delete an account and output the result in json format
  permguard accounts delete --account 268786704340 --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteAccount(deps, cmd, v)
		},
	}
	command.Flags().Int64(aziclicommon.FlagCommonAccountID, 0, "account id")
	v.BindPFlag(azoptions.FlagName(commandNameForAccountsDelete, aziclicommon.FlagCommonAccountID), command.Flags().Lookup(aziclicommon.FlagCommonAccountID))
	return command
}
