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

// runECommandForUpsertAccount runs the command for creating or updating an account.
func runECommandForUpsertAccount(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	if deps == nil {
		color.Red("cli: an issue has been detected with the cli code configuration. please create a github issue with the details")
		return aziclicommon.ErrCommandSilent
	}
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
	name := v.GetString(azoptions.FlagName(flagPrefix, aziclicommon.FlagCommonName))
	var account *azmodels.Account
	if isCreate {
		account, err = client.CreateAccount(name)
	} else {
		accountID := v.GetInt64(azoptions.FlagName(flagPrefix, aziclicommon.FlagCommonAccountID))
		inputAccount := &azmodels.Account{
			AccountID: accountID,
			Name:      name,
		}
		account, err = client.UpdateAccount(inputAccount)
	}
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed to complete the operation.")
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
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
	printer.PrintlnMap(output)
	return nil
}

// runECommandForAccounts runs the command for managing accounts.
func runECommandForAccounts(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// CreateCommandForAccounts creates a command for managing accounts.
func CreateCommandForAccounts(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "accounts",
		Short: "Manage accounts on the remote server",
		Long:  aziclicommon.BuildCliLongTemplate(`This command manages accounts on the remote server.`),
		RunE:  runECommandForAccounts,
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azoptions.FlagName(commandNameForAccountsList, aziclicommon.FlagCommonAccountID), command.Flags().Lookup(aziclicommon.FlagCommonAccountID))

	command.AddCommand(createCommandForAccountCreate(deps, v))
	command.AddCommand(createCommandForAccountUpdate(deps, v))
	command.AddCommand(createCommandForAccountDelete(deps, v))
	command.AddCommand(createCommandForAccountList(deps, v))
	return command
}
