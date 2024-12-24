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
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForLedgersList is the command name for ledgers list.
	commandNameForLedgersList = "ledgers.list"
)

// runECommandForListLedgers runs the command for creating a ledger.
func runECommandForListLedgers(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	papTarget := ctx.GetPAPTarget()
	client, err := deps.CreateGrpcPAPClient(papTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid pap target %s", papTarget))
		return aziclicommon.ErrCommandSilent
	}
	page := v.GetInt32(azoptions.FlagName(commandNameForLedgersList, aziclicommon.FlagCommonPage))
	pageSize := v.GetInt32(azoptions.FlagName(commandNameForLedgersList, aziclicommon.FlagCommonPageSize))
	applicationID := v.GetInt64(azoptions.FlagName(commandNameForLedger, aziclicommon.FlagCommonApplicationID))
	ledgerID := v.GetString(azoptions.FlagName(commandNameForLedgersList, flagLedgerID))
	name := v.GetString(azoptions.FlagName(commandNameForLedgersList, aziclicommon.FlagCommonName))
	ledgers, err := client.FetchLedgersBy(page, pageSize, applicationID, ledgerID, name)
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed to list ledgers.")
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, ledger := range ledgers {
			ledgerID := ledger.LedgerID
			ledgerName := ledger.Name
			output[ledgerID] = ledgerName
		}
	} else if ctx.IsJSONOutput() {
		output["ledgers"] = ledgers
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForLedgerList creates a command for managing ledgerlist.
func createCommandForLedgerList(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote ledgers",
		Long: aziclicommon.BuildCliLongTemplate(`This command lists all remote ledgers.

Examples:
  # list all ledgers and output in json format
  permguard authz repos list --application 268786704340 --output json
  # list all ledgers filtered by name
  permguard authz repos list --application 268786704340 --name v1
  # list all ledgers filtered by ledger id
  permguard authz repos list --application 268786704340 --ledgerid 668f3771eacf4094ba8a80942ea5fd3f
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListLedgers(deps, cmd, v)
		},
	}
	command.Flags().Int32P(aziclicommon.FlagCommonPage, aziclicommon.FlagCommonPageShort, 1, "specify the page number for paginated results")
	v.BindPFlag(azoptions.FlagName(commandNameForLedgersList, aziclicommon.FlagCommonPage), command.Flags().Lookup(aziclicommon.FlagCommonPage))
	command.Flags().Int32P(aziclicommon.FlagCommonPageSize, aziclicommon.FlagCommonPageSizeShort, 1000, "specify the number of results per page")
	v.BindPFlag(azoptions.FlagName(commandNameForLedgersList, aziclicommon.FlagCommonPageSize), command.Flags().Lookup(aziclicommon.FlagCommonPageSize))
	command.Flags().String(flagLedgerID, "", "filter results by ledger id")
	v.BindPFlag(azoptions.FlagName(commandNameForLedgersList, flagLedgerID), command.Flags().Lookup(flagLedgerID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "filter results by ledger name")
	v.BindPFlag(azoptions.FlagName(commandNameForLedgersList, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
