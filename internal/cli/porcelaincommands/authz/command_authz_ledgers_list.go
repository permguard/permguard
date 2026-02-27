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
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForLedgersList is the command name for ledgers list.
	commandNameForLedgersList = "ledgers-list"
)

// runECommandForListLedgers runs the command for creating a ledger.
func runECommandForListLedgers(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	papEndpoint, err := ctx.PAPEndpoint()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list ledgers.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to list ledgers"), err))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcPAPClient(papEndpoint)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list ledgers.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to list ledgers"), err))
		}
		return common.ErrCommandSilent
	}
	page := v.GetInt32(options.FlagName(commandNameForLedgersList, common.FlagCommonPage))
	pageSize := v.GetInt32(options.FlagName(commandNameForLedgersList, common.FlagCommonPageSize))
	zoneID := v.GetInt64(options.FlagName(commandNameForLedger, common.FlagCommonZoneID))
	ledgerID := v.GetString(options.FlagName(commandNameForLedgersList, flagLedgerID))
	kind := v.GetString(options.FlagName(commandNameForLedgersList, flagLedgerKind))
	name := v.GetString(options.FlagName(commandNameForLedgersList, common.FlagCommonName))
	ledgers, err := client.FetchLedgersBy(page, pageSize, zoneID, ledgerID, kind, name)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list ledgers.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to list ledgers"), err))
		}
		return common.ErrCommandSilent
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
func createCommandForLedgerList(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote ledgers",
		Long: common.BuildCliLongTemplate(`This command lists all remote ledgers.

Examples:
  # list all ledgers and output in json format
  permguard authz ledgers list --zone-id 273165098782 --output json
  # list all ledgers filtered by name
  permguard authz ledgers list --zone-id 273165098782 --name v1
  # list all ledgers filtered by ledger id
  permguard authz ledgers list --zone-id 273165098782 --ledger-id 668f3771eacf4094ba8a80942ea5fd3f
		`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForListLedgers(deps, cmd, v)
		},
	}

	command.Flags().Int32P(common.FlagCommonPage, common.FlagCommonPageShort, 1, "specify the page number for paginated results")
	_ = v.BindPFlag(options.FlagName(commandNameForLedgersList, common.FlagCommonPage), command.Flags().Lookup(common.FlagCommonPage))

	command.Flags().Int32P(common.FlagCommonPageSize, common.FlagCommonPageSizeShort, 1000, "specify the number of results per page")
	_ = v.BindPFlag(options.FlagName(commandNameForLedgersList, common.FlagCommonPageSize), command.Flags().Lookup(common.FlagCommonPageSize))

	command.Flags().String(flagLedgerID, "", "filter results by ledger id")
	_ = v.BindPFlag(options.FlagName(commandNameForLedgersList, flagLedgerID), command.Flags().Lookup(flagLedgerID))

	command.Flags().String(common.FlagCommonName, "", "filter results by ledger name")
	_ = v.BindPFlag(options.FlagName(commandNameForLedgersList, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
