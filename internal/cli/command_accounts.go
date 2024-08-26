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
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

// runECommandForUpsertAccount runs the command for creating or updating an account.
func runECommandForUpsertAccount(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	if deps == nil {
		color.Red(errorMessageCliBug)
		return ErrCommandSilent
	}
	ctx, printer, err := deps.CreateContextAndPrinter(cmd, v)
	if err != nil {
		color.Red(errorMessageCliBug)
		return ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := aziclients.NewGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return ErrCommandSilent
	}
	name := v.GetString(azconfigs.FlagName(flagPrefix, flagCommonName))
	var account *azmodels.Account
	if isCreate {
		account, err = client.CreateAccount(name)
	} else {
		accountID := v.GetInt64(azconfigs.FlagName(flagPrefix, flagCommonAccountID))
		inputAccount := &azmodels.Account{
			AccountID: accountID,
			Name:      name,
		}
		account, err = client.UpdateAccount(inputAccount)
	}
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
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

// runECommandForAccounts runs the command for managing accounts.
func runECommandForAccounts(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForAccounts creates a command for managing accounts.
func createCommandForAccounts(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "accounts",
		Short: "Manage Accounts",
		Long:  fmt.Sprintf(cliLongTemplate, `This command manages accounts.`),
		RunE:  runECommandForAccounts,
	}

	command.PersistentFlags().Int64(flagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForAccountsList, flagCommonAccountID), command.Flags().Lookup(flagCommonAccountID))

	command.AddCommand(createCommandForAccountCreate(deps, v))
	command.AddCommand(createCommandForAccountUpdate(deps, v))
	command.AddCommand(createCommandForAccountDelete(deps, v))
	command.AddCommand(createCommandForAccountList(deps, v))
	return command
}
