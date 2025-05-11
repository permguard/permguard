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
	// commandNameForTenantsCreate is the command name for tenants create.
	commandNameForTenantsCreate = "tenants-create"
)

// runECommandForCreateTenant runs the command for creating a tenant.
func runECommandForCreateTenant(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertTenant(deps, cmd, v, commandNameForTenantsCreate, true)
}

// createCommandForTenantCreate creates a command for managing tenantcreate.
func createCommandForTenantCreate(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a remote tenant",
		Long: common.BuildCliLongTemplate(`This command creates a remote tenant.

Examples:
  # create a tenant and output the result in json format
  permguard authn tenants create --zone-id 273165098782 --name matera-branch --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCreateTenant(deps, cmd, v)
		},
	}
	command.Flags().String(common.FlagCommonName, "", "specify the name of the tenant to create")
	v.BindPFlag(options.FlagName(commandNameForTenantsCreate, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
