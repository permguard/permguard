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

package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForIdentitiesUpdate = "identities.update"
)

// runECommandForUpdateIdentity runs the command for creating an identity.
func runECommandForUpdateIdentity(cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertIdentity(cmd, v, commandNameForIdentitiesUpdate, false)
}

// createCommandForIdentityUpdate creates a command for managing identityupdate.
func createCommandForIdentityUpdate(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update an identity",
		Long: `This command update an identity.

Examples:
  # update an identity with name identity1, id 19159d69-e902-418e-966a-148c4d5169a4 and account 301990992055
  permguard authn identities update --account 301990992055 --identityid 19159d69-e902-418e-966a-148c4d5169a4 --name identity1
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateIdentity(cmd, v)
		},
	}
	command.Flags().String(flagIdentityID, "", "identity id")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesUpdate, flagIdentityID), command.Flags().Lookup(flagIdentityID))
	command.Flags().String(flagIdentityKind, "", "identity kind")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesUpdate, flagIdentityKind), command.Flags().Lookup(flagIdentityKind))
	command.Flags().String(flagCommonName, "", "identity name")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesUpdate, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
