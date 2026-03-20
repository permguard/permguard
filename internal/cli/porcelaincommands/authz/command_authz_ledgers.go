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
	"github.com/permguard/permguard/pkg/core/validators"
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

// failWithDetails drains any buffered verbose details and prints the error with details.
func failWithDetails(ctx *common.CliCommandContext, printer cli.Printer, err error) error {
	output := map[string]any{}
	if ctx.IsVerboseTerminalOutput() {
		details := ctx.DrainVerboseDetails()
		for _, d := range details {
			dtype, _ := d["type"].(string)
			switch dtype {
			case "action":
				if msg, ok := d["message"].(string); ok {
					color.HiBlack("%s\n", msg)
				}
			case "file":
				if path, ok := d["path"].(string); ok {
					color.HiBlack("file: %s\n", path)
				}
			case "network":
				endpoint, _ := d["endpoint"].(string)
				operation, _ := d["operation"].(string)
				color.HiBlack("network: %s [%s]\n", endpoint, operation)
			}
		}
	} else if ctx.IsVerboseJSONOutput() {
		details := ctx.DrainVerboseDetails()
		if details == nil {
			details = []map[string]any{}
		}
		output["details"] = details
	}
	printer.ErrorWithOutput(output, err)
	return common.ErrCommandSilent
}

// runECommandForCreateLedger runs the command for creating a ledger.
func runECommandForUpsertLedger(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
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
	papEndpoint, err := ctx.PAPEndpoint()
	if err != nil {
		return failWithDetails(ctx, printer, errors.Join(fmt.Errorf("cli: cli: %s", strings.ToLower(opGetErroMessage(isCreate))), err))
	}
	tlsCfg := ctx.TLSClientConfig()
	client, err := deps.CreateGrpcPAPClient(papEndpoint, tlsCfg, ctx.VerboseCollector())
	if err != nil {
		return failWithDetails(ctx, printer, errors.Join(fmt.Errorf("cli: cli: %s", strings.ToLower(opGetErroMessage(isCreate))), err))
	}
	defer func() { _ = client.Close() }()
	zoneID := v.GetInt64(options.FlagName(commandNameForLedger, common.FlagCommonZoneID))
	if zoneID == 0 {
		return failWithDetails(ctx, printer, errors.New("cli: --zone-id is required"))
	}
	if zoneID < 0 {
		return failWithDetails(ctx, printer, errors.New("cli: --zone-id must be a positive integer"))
	}
	ledger := &pap.Ledger{ZoneID: zoneID}
	if isCreate {
		name := v.GetString(options.FlagName(flagPrefix, common.FlagCommonName))
		if err := validators.ValidateName("ledger", name); err != nil {
			return failWithDetails(ctx, printer, errors.Join(errors.New("cli: invalid ledger name"), err))
		}
		ledger.Name = name
		ledger, err = client.CreateLedger(zoneID, "policy", name)
	} else {
		ledgerID := v.GetString(options.FlagName(flagPrefix, flagLedgerID))
		if ledgerID == "" {
			return failWithDetails(ctx, printer, errors.New("cli: --ledger-id is required"))
		}
		name := v.GetString(options.FlagName(flagPrefix, common.FlagCommonName))
		if err := validators.ValidateName("ledger", name); err != nil {
			return failWithDetails(ctx, printer, errors.Join(errors.New("cli: invalid ledger name"), err))
		}
		ledger.LedgerID = ledgerID
		ledger.Name = name
		ledger, err = client.UpdateLedger(ledger)
	}
	if err != nil {
		return failWithDetails(ctx, printer, errors.Join(fmt.Errorf("cli: cli: %s", strings.ToLower(opGetErroMessage(isCreate))), err))
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		ledgerID := ledger.LedgerID
		ledgerName := ledger.Name
		output[ledgerID] = ledgerName
	} else if ctx.IsJSONOutput() {
		output["ledgers"] = []*pap.Ledger{ledger}
	}
	if ctx.IsVerboseJSONOutput() {
		details := ctx.DrainVerboseDetails()
		if details == nil {
			details = []map[string]any{}
		}
		output["details"] = details
	}
	printer.PrintlnMap(output)
	return nil
}

// runECommandForLedgers runs the command for managing ledgers.
func runECommandForLedgers(cmd *cobra.Command, _ []string) error {
	return cmd.Help()
}

// createCommandForLedgers creates a command for managing ledgers.
func createCommandForLedgers(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "ledgers",
		Short: "Manage ledgers on the remote server",
		Long:  common.BuildCliLongTemplate(`This command manages ledgers on the remote server.`),
		Args:  cobra.NoArgs,
		RunE:  runECommandForLedgers,
	}

	command.PersistentFlags().Int64(common.FlagCommonZoneID, 0, "zone id")
	_ = v.BindPFlag(options.FlagName(commandNameForLedger, common.FlagCommonZoneID), command.PersistentFlags().Lookup(common.FlagCommonZoneID))
	command.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		if strings.Contains(err.Error(), "zone-id") {
			return errors.New("cli: --zone-id must be a valid positive integer")
		}
		return err
	})

	command.AddCommand(createCommandForLedgerCreate(deps, v))
	command.AddCommand(createCommandForLedgerUpdate(deps, v))
	command.AddCommand(createCommandForLedgerDelete(deps, v))
	command.AddCommand(createCommandForLedgerList(deps, v))
	return command
}
