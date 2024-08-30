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
	// commandNameForIdentitiesCreate is the command name for identities create.
	commandNameForIdentitiesCreate = "identities.create"
)

// runECommandForCreateIdentity runs the command for creating an identity.
func runECommandForCreateIdentity(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertIdentity(deps, cmd, v, commandNameForIdentitiesCreate, true)
}

// createCommandForIdentityCreate creates a command for managing identitycreate.
func createCommandForIdentityCreate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a remote identity",
		Long: aziclicommon.BuildCliLongTemplate(`This command creates a remote identity.

Examples:
  # create an user identity and output the result in json format
  permguard authn identities create --account 268786704340 --kind user --name nicolagallo --identitysourceid 1da1d9094501425085859c60429163c2 --output json
  # create a role identity and output the result in json format
  permguard authn identities create --account 268786704340 --kind role --name branch-manager --identitysourceid 1da1d9094501425085859c60429163c2 --output json

		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCreateIdentity(deps, cmd, v)
		},
	}
	command.Flags().String(flagIdentitySourceID, "", "identity source id")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesCreate, flagIdentitySourceID), command.Flags().Lookup(flagIdentitySourceID))
	command.Flags().String(flagIdentityKind, "", "identity kind")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesCreate, flagIdentityKind), command.Flags().Lookup(flagIdentityKind))
	command.Flags().String(aziclicommon.FlagCommonName, "", "identity name")
	v.BindPFlag(azconfigs.FlagName(commandNameForIdentitiesCreate, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
