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
	"net"

	"google.golang.org/grpc/status"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclients "github.com/permguard/permguard/internal/agents/clients"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

// runECommandForUpsertAccount runs the command for creating or updating an account.
func runECommandForUpsertAccount(cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	ctx, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red("invalid inputs")
		return ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := aziclients.NewGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Sprintf("invalid aap target %s", aapTarget), err)
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
		if _, ok := status.FromError(err); ok {
			printer.Error("server cannot be reached", nil)
		} else if netErr, ok := err.(*net.OpError); ok {
			printer.Error("server cannot be reached", netErr)
		} else {
			printer.Error("operation cannot be completed", err)
		}
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
func createCommandForAccounts(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "accounts",
		Short: "Manage Accounts",
		Long:  `This command manages accounts.`,
		RunE:  runECommandForAccounts,
	}

	command.PersistentFlags().Int64(flagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForAccountsList, flagCommonAccountID), command.Flags().Lookup(flagCommonAccountID))

	command.AddCommand(createCommandForAccountCreate(v))
	command.AddCommand(createCommandForAccountUpdate(v))
	command.AddCommand(createCommandForAccountDelete(v))
	command.AddCommand(createCommandForAccountList(v))
	return command
}
