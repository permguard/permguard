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
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

const (
	// commandNameForLedger is the command name for ledger.
	commandNameForLedger = "ledger"
	// flagLedgerID is the flag for ledger id.
	flagLedgerID = "ledger-id"
	// flagLedgerKind is the flag for ledger kind.
	flagLedgerKind = "kind"
)

// runECommandForCreateLedger runs the command for creating a ledger.
func runECommandForUpsertLedger(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	opGetErroMessage := func(op bool) string {
		if op {
			return "Failed to create the ledger"
		}
		return "Failed to upsert the ledger"
	}
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	papTarget, err := ctx.PAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New(strings.ToLower(opGetErroMessage(isCreate)))))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcPAPClient(papTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New(strings.ToLower(opGetErroMessage(isCreate)))))
		}
		return common.ErrCommandSilent
	}
	zoneID := v.GetInt64(options.FlagName(commandNameForLedger, common.FlagCommonZoneID))
	name := v.GetString(options.FlagName(flagPrefix, common.FlagCommonName))
	ledger := &pap.Ledger{
		ZoneID: zoneID,
		Name:   name,
	}
	if isCreate {
		ledger, err = client.CreateLedger(zoneID, "policy", name)
	} else {
		ledgerID := v.GetString(options.FlagName(flagPrefix, flagLedgerID))
		ledger.LedgerID = ledgerID
		ledger, err = client.UpdateLedger(ledger)
	}
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New(strings.ToLower(opGetErroMessage(isCreate)))))
		}
		return common.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		ledgerID := ledger.LedgerID
		ledgerName := ledger.Name
		output[ledgerID] = ledgerName
	} else if ctx.IsJSONOutput() {
		output["ledgers"] = []*pap.Ledger{ledger}
	}
	printer.PrintlnMap(output)
	return nil
}

// runECommandForLedgers runs the command for managing ledgers.
func runECommandForLedgers(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForLedgers creates a command for managing ledgers.
func createCommandForLedgers(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "ledgers",
		Short: "Manage ledgers on the remote server",
		Long:  common.BuildCliLongTemplate(`This command manages ledgers on the remote server.`),
		RunE:  runECommandForLedgers,
	}

	command.PersistentFlags().Int64(common.FlagCommonZoneID, 0, "zone id")
	v.BindPFlag(options.FlagName(commandNameForLedger, common.FlagCommonZoneID), command.PersistentFlags().Lookup(common.FlagCommonZoneID))

	command.AddCommand(createCommandForLedgerCreate(deps, v))
	command.AddCommand(createCommandForLedgerUpdate(deps, v))
	command.AddCommand(createCommandForLedgerDelete(deps, v))
	command.AddCommand(createCommandForLedgerList(deps, v))
	return command
}
