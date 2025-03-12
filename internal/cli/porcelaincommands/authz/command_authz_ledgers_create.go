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
	// commandNameForLedgersCreate is the command name for ledgers create.
	commandNameForLedgersCreate = "ledgers-create"
)

// runECommandForCreateLedger runs the command for creating a ledger.
func runECommandForCreateLedger(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertLedger(deps, cmd, v, commandNameForLedgersCreate, true)
}

// createCommandForLedgerCreate creates a command for managing ledgercreate.
func createCommandForLedgerCreate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a remote ledger",
		Long: aziclicommon.BuildCliLongTemplate(`This command creates a remote ledger.

Examples:
  # create a ledger and output the result in json format
  permguard authz ledgers create --zone-id 273165098782 --name magicfarmacia --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCreateLedger(deps, cmd, v)
		},
	}
	command.Flags().String(aziclicommon.FlagCommonName, "", "specify the name of the ledger to create")
	v.BindPFlag(azoptions.FlagName(commandNameForLedgersCreate, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
