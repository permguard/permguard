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
	commandNameForLedgersDelete = "ledgers.delete"
)

// runECommandForDeleteLedger runs the command for creating a ledger.
func runECommandForDeleteLedger(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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
	zoneID := v.GetInt64(azoptions.FlagName(commandNameForLedger, aziclicommon.FlagCommonZoneID))
	ledgerID := v.GetString(azoptions.FlagName(commandNameForLedgersDelete, flagLedgerID))
	ledger, err := client.DeleteLedger(zoneID, ledgerID)
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed to delete the ledger.")
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

// createCommandForLedgerDelete creates a command for managing ledgerdelete.
func createCommandForLedgerDelete(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a remote ledger",
		Long: aziclicommon.BuildCliLongTemplate(`This command deletes a remote ledger.

Examples:
  # delete a ledger and output the result in json format
  permguard authz ledgers delete --zoneid 268786704340 --ledgerid 668f3771eacf4094ba8a80942ea5fd3f --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteLedger(deps, cmd, v)
		},
	}
	command.Flags().String(flagLedgerID, "", "specify the ID of the ledger to delete")
	v.BindPFlag(azoptions.FlagName(commandNameForLedgersDelete, flagLedgerID), command.Flags().Lookup(flagLedgerID))
	return command
}
