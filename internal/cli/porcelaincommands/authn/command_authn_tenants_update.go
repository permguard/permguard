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
	// commandNameForTenantsUpdate is the command name for tenants update.
	commandNameForTenantsUpdate = "tenants-update"
)

// runECommandForUpdateTenant runs the command for creating a tenant.
func runECommandForUpdateTenant(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertTenant(deps, cmd, v, commandNameForTenantsUpdate, false)
}

// createCommandForTenantUpdate creates a command for managing tenantupdate.
func createCommandForTenantUpdate(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update a remote tenant",
		Long: common.BuildCliLongTemplate(`This command updates a remote tenant.

Examples:
  # update a tenant and output the result in json format
  permguard authn tenants update --zone-id 273165098782 --tenant-id 2e190ee712494838bb54d67e2a0c496a --name atera-branch
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateTenant(deps, cmd, v)
		},
	}
	command.Flags().String(flagTenantID, "", "specify the id of the tenant to update")
	v.BindPFlag(options.FlagName(commandNameForTenantsUpdate, flagTenantID), command.Flags().Lookup(flagTenantID))
	command.Flags().String(common.FlagCommonName, "", "specify the new name for the tenant")
	v.BindPFlag(options.FlagName(commandNameForTenantsUpdate, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
