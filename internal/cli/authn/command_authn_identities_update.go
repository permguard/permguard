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

package authn

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	// commandNameForIdentitiesUpdate is the command name for identities update.
	commandNameForIdentitiesUpdate = "identities.update"
)

// runECommandForUpdateIdentity runs the command for creating an identity.
func runECommandForUpdateIdentity(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertIdentity(deps, cmd, v, commandNameForIdentitiesUpdate, false)
}

// createCommandForIdentityUpdate creates a command for managing identityupdate.
func createCommandForIdentityUpdate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update an identity",
		Long: aziclicommon.BuildCliLongTemplate(`This command updates an identity.

Examples:
  # update and identity and output the result in json format
  permguard authn identities update --account 268786704340 --identityid 804ecc6b562242069c7837f63fd1a3b3 --kind user --name nicolagallo --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateIdentity(deps, cmd, v)
		},
	}
	command.Flags().String(flagIdentityID, "", "identity id")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesUpdate, flagIdentityID), command.Flags().Lookup(flagIdentityID))
	command.Flags().String(flagIdentityKind, "", "identity kind")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesUpdate, flagIdentityKind), command.Flags().Lookup(flagIdentityKind))
	command.Flags().String(aziclicommon.FlagCommonName, "", "identity name")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesUpdate, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}