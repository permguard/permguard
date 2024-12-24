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

package applications

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForApplicationsUpdate is the command name for applications update.
	commandNameForApplicationsUpdate = "applications.update"
)

// runECommandForUpdateApplication runs the command for creating an application.
func runECommandForUpdateApplication(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertApplication(deps, cmd, v, commandNameForApplicationsUpdate, false)
}

// createCommandForApplicationUpdate creates a command for managing applicationupdate.
func createCommandForApplicationUpdate(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update a remote application",
		Long: aziclicommon.BuildCliLongTemplate(`This command updates a remote application.

Examples:
  # update an application and output the result in json format
  permguard applications update --appid 268786704340 --name magicfarmacia-dev --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateApplication(deps, cmd, v)
		},
	}
	command.Flags().Int64(aziclicommon.FlagCommonApplicationID, 0, "specify the application id to update")
	v.BindPFlag(azoptions.FlagName(commandNameForApplicationsUpdate, aziclicommon.FlagCommonApplicationID), command.Flags().Lookup(aziclicommon.FlagCommonApplicationID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "specify the new application name")
	v.BindPFlag(azoptions.FlagName(commandNameForApplicationsUpdate, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
