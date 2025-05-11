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

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForIdentitiesUpdate is the command name for identities update.
	commandNameForIdentitiesUpdate = "identities-update"
)

// runECommandForUpdateIdentity runs the command for creating an identity.
func runECommandForUpdateIdentity(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertIdentity(deps, cmd, v, commandNameForIdentitiesUpdate, false)
}

// createCommandForIdentityUpdate creates a command for managing identityupdate.
func createCommandForIdentityUpdate(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update a remote identity",
		Long: common.BuildCliLongTemplate(`This command updates a remote identity.

Examples:
  # update and identity and output the result in json format
  permguard authn identities update --zone-id 273165098782 --identity-id 804ecc6b562242069c7837f63fd1a3b3 --kind user --name nicolagallo --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateIdentity(deps, cmd, v)
		},
	}
	command.Flags().String(flagIdentityID, "", "specify the id of the identity to update")
	v.BindPFlag(options.FlagName(commandNameForIdentitiesUpdate, flagIdentityID), command.Flags().Lookup(flagIdentityID))
	command.Flags().String(flagIdentityKind, "", "specify the new type of the identity")
	v.BindPFlag(options.FlagName(commandNameForIdentitiesUpdate, flagIdentityKind), command.Flags().Lookup(flagIdentityKind))
	command.Flags().String(common.FlagCommonName, "", "specify the new name for the identity")
	v.BindPFlag(options.FlagName(commandNameForIdentitiesUpdate, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
