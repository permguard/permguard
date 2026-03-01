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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForLedgersUpdate is the command name for ledgers update.
	commandNameForLedgersUpdate = "ledgers-update"
)

// runECommandForUpdateLedger runs the command for creating a ledger.
func runECommandForUpdateLedger(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertLedger(deps, cmd, v, commandNameForLedgersUpdate, false)
}

// createCommandForLedgerUpdate creates a command for managing ledgerupdate.
func createCommandForLedgerUpdate(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update a remote ledger",
		Long: common.BuildCliLongTemplate(`This command updates a remote ledger.

Examples:
  # update a ledger
  permguard authz ledgers update --zone-id 273165098782 --ledger-id 668f3771eacf4094ba8a80942ea5fd3f v1.1
  # update a ledger and output the result in json format
  permguard authz ledgers update --zone-id 273165098782 --ledger-id 668f3771eacf4094ba8a80942ea5fd3f v1.1 --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && !cmd.Flags().Changed(common.FlagCommonName) {
				_ = cmd.Flags().Set(common.FlagCommonName, args[0])
			}
			return runECommandForUpdateLedger(deps, cmd, v)
		},
	}
	command.Flags().String(flagLedgerID, "", "specify the ID of the ledger to update")
	_ = v.BindPFlag(options.FlagName(commandNameForLedgersUpdate, flagLedgerID), command.Flags().Lookup(flagLedgerID))
	command.Flags().String(common.FlagCommonName, "", "specify the new name for the ledger")
	_ = v.BindPFlag(options.FlagName(commandNameForLedgersUpdate, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
