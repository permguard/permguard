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
	azmodelspap "github.com/permguard/permguard/pkg/transport/models/pap"
)

const (
	// commandNameForLedger is the command name for ledger.
	commandNameForLedger = "ledger"
	// flagLedgerID is the flag for ledger id.
	flagLedgerID = "ledgerid"
	// flagLedgerKind is the flag for ledger kind.
	flagLedgerKind = "kind"
)

// runECommandForCreateLedger runs the command for creating a ledger.
func runECommandForUpsertLedger(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	papTarget, err := ctx.GetPAPTarget()
	if err != nil {
		printer.Error(fmt.Errorf("invalid pap target %s", papTarget))
		return aziclicommon.ErrCommandSilent
	}
	client, err := deps.CreateGrpcPAPClient(papTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid pap target %s", papTarget))
		return aziclicommon.ErrCommandSilent
	}
	zoneID := v.GetInt64(azoptions.FlagName(commandNameForLedger, aziclicommon.FlagCommonZoneID))
	name := v.GetString(azoptions.FlagName(flagPrefix, aziclicommon.FlagCommonName))
	ledger := &azmodelspap.Ledger{
		ZoneID: zoneID,
		Name:   name,
	}
	if isCreate {
		ledger, err = client.CreateLedger(zoneID, "policy", name)
	} else {
		ledgerID := v.GetString(azoptions.FlagName(flagPrefix, flagLedgerID))
		ledger.LedgerID = ledgerID
		ledger, err = client.UpdateLedger(ledger)
	}
	if err != nil {
		if ctx.IsTerminalOutput() {
			if isCreate {
				printer.Println("Failed to create the ledger.")
			} else {
				printer.Println("Failed to update the ledger.")
			}
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		ledgerID := ledger.LedgerID
		ledgerName := ledger.Name
		output[ledgerID] = ledgerName
	} else if ctx.IsJSONOutput() {
		output["ledgers"] = []*azmodelspap.Ledger{ledger}
	}
	printer.PrintlnMap(output)
	return nil
}

// runECommandForLedgers runs the command for managing ledgers.
func runECommandForLedgers(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForLedgers creates a command for managing ledgers.
func createCommandForLedgers(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "ledgers",
		Short: "Manage ledgers on the remote server",
		Long:  aziclicommon.BuildCliLongTemplate(`This command manages ledgers on the remote server.`),
		RunE:  runECommandForLedgers,
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonZoneID, 0, "zone id")
	v.BindPFlag(azoptions.FlagName(commandNameForLedger, aziclicommon.FlagCommonZoneID), command.PersistentFlags().Lookup(aziclicommon.FlagCommonZoneID))

	command.AddCommand(createCommandForLedgerCreate(deps, v))
	command.AddCommand(createCommandForLedgerUpdate(deps, v))
	command.AddCommand(createCommandForLedgerDelete(deps, v))
	command.AddCommand(createCommandForLedgerList(deps, v))
	return command
}
