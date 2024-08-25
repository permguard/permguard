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
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForTenantsCreate = "tenants.create"
)

// runECommandForCreateTenant runs the command for creating a tenant.
func runECommandForCreateTenant(cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertTenant(cmd, v, commandNameForTenantsCreate, true)
}

// createCommandForTenantCreate creates a command for managing tenantcreate.
func createCommandForTenantCreate(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a tenant",
		Long: fmt.Sprintf(cliLongTemplate, `This command creates a tenant.

Examples:
  # create a tenant with name tenant1 and account 301990992055
  permguard authn tenants create --account 301990992055 --name tenant1
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCreateTenant(cmd, v)
		},
	}
	command.Flags().String(flagCommonName, "", "tenant name")
	v.BindPFlag(azconfigs.FlagName(commandNameForTenantsCreate, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
