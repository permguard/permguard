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
	commandNameForTenantsUpdate = "tenants.update"
)

// runECommandForUpdateTenant runs the command for creating a tenant.
func runECommandForUpdateTenant(cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertTenant(cmd, v, commandNameForTenantsUpdate, false)
}

// createCommandForTenantUpdate creates a command for managing tenantupdate.
func createCommandForTenantUpdate(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update a tenant",
		Long: `This command update a tenant.

Examples:
  # update a tenant with name tenant1, id 19159d69-e902-418e-966a-148c4d5169a4 and account 301990992055
  permguard authn tenants update --account 301990992055 --tenantid 19159d69-e902-418e-966a-148c4d5169a4 --name tenant1
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateTenant(cmd, v)
		},
	}
	command.Flags().String(flagTenantID, "", "tenant id")
	v.BindPFlag(azconfigs.FlagName(commandNameForTenantsUpdate, flagTenantID), command.Flags().Lookup(flagTenantID))
	command.Flags().String(flagCommonName, "", "tenant name")
	v.BindPFlag(azconfigs.FlagName(commandNameForTenantsUpdate, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
