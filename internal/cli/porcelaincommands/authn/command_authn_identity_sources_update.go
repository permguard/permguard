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
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForIdentitySourcesUpdate is the command name for identity sources update.
	commandNameForIdentitySourcesUpdate = "identitysources-update"
)

// runECommandForUpdateIdentitySource runs the command for creating an identity source.
func runECommandForUpdateIdentitySource(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertIdentitySource(deps, cmd, v, commandNameForIdentitySourcesUpdate, false)
}

// createCommandForIdentitySourceUpdate creates a command for managing identity source update.
func createCommandForIdentitySourceUpdate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update a remote identity source",
		Long: aziclicommon.BuildCliLongTemplate(`This command updates a remote identity source.

Examples:
  # update an identity source and output the result in json format
  permguard authn identitysources update --zone-id 268786704340 --identitysource-id1da1d9094501425085859c60429163c2 --name google --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateIdentitySource(deps, cmd, v)
		},
	}
	command.Flags().String(flagIdentitySourceID, "", "specify the id of the identity source to update")
	v.BindPFlag(azoptions.FlagName(commandNameForIdentitySourcesUpdate, flagIdentitySourceID), command.Flags().Lookup(flagIdentitySourceID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "specify the new name for the identity source")
	v.BindPFlag(azoptions.FlagName(commandNameForIdentitySourcesUpdate, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
