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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForLedgersUpdate is the command name for ledgers update.
	commandNameForLedgersUpdate = "ledgers.update"
)

// runECommandForUpdateLedger runs the command for creating a ledger.
func runECommandForUpdateLedger(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertLedger(deps, cmd, v, commandNameForLedgersUpdate, false)
}

// createCommandForLedgerUpdate creates a command for managing ledgerupdate.
func createCommandForLedgerUpdate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update a remote ledger",
		Long: aziclicommon.BuildCliLongTemplate(`This command updates a remote ledger.

Examples:
  # update a ledger and output the result in json format
  permguard authz ledgers update --zoneid 268786704340 --ledgerid 668f3771eacf4094ba8a80942ea5fd3f --name v1.1 --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateLedger(deps, cmd, v)
		},
	}
	command.Flags().String(flagLedgerID, "", "specify the ID of the ledger to update")
	v.BindPFlag(azoptions.FlagName(commandNameForLedgersUpdate, flagLedgerID), command.Flags().Lookup(flagLedgerID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "specify the new name for the ledger")
	v.BindPFlag(azoptions.FlagName(commandNameForLedgersUpdate, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
