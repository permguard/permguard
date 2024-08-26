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

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForTenantsList = "tenants.list"
)

// runECommandForListTenants runs the command for creating a tenant.
func runECommandForListTenants(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := createContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(errorMessageCliBug)
		return ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := deps.CreateGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return ErrCommandSilent
	}
	page := v.GetInt32(azconfigs.FlagName(commandNameForAccountsList, flagCommonPage))
	pageSize := v.GetInt32(azconfigs.FlagName(commandNameForAccountsList, flagCommonPageSize))
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForTenant, flagCommonAccountID))
	tenantID := v.GetString(azconfigs.FlagName(commandNameForTenantsList, flagTenantID))
	name := v.GetString(azconfigs.FlagName(commandNameForTenantsList, flagCommonName))
	tenants, err := client.FetchTenantsBy(page, pageSize, accountID, tenantID, name)
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, tenant := range tenants {
			tenantID := tenant.TenantID
			tenantName := tenant.Name
			output[tenantID] = tenantName
		}
	} else if ctx.IsJSONOutput() {
		output["tenants"] = tenants
	}
	printer.Print(output)
	return nil
}

// createCommandForTenantList creates a command for managing tenantlist.
func createCommandForTenantList(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List tenants",
		Long: fmt.Sprintf(cliLongTemplate, `This command lists all tenants.

Examples:
  # list all tenants for account 301990992055
  permguard authn tenants list --account 301990992055
  # list all tenants for account 301990992055 and filter by name tenant1
  permguard authn tenants list --account 301990992055 --name tenant1
  # list all tenants for account 301990992055 and filter by tenant id 377532e1-befe-47cb-a55a-0a789c5ec8fd
  permguard authn tenants list --account 301990992055 --tenantid 377532e1-befe-47cb-a55a-0a789c5ec8fd
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListTenants(deps, cmd, v)
		},
	}
	command.Flags().Int32P(flagCommonPage, flagCommonPageShort, 1, "page number")
	v.BindPFlag(azconfigs.FlagName(commandNameForAccountsList, flagCommonPage), command.Flags().Lookup(flagCommonPage))
	command.Flags().Int32P(flagCommonPageSize, flagCommonPageSizeShort, 1000, "page size")
	v.BindPFlag(azconfigs.FlagName(commandNameForAccountsList, flagCommonPageSize), command.Flags().Lookup(flagCommonPageSize))
	command.Flags().String(flagTenantID, "", "tenant id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForTenantsList, flagTenantID), command.Flags().Lookup(flagTenantID))
	command.Flags().String(flagCommonName, "", "tenant name filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForTenantsList, flagCommonName), command.Flags().Lookup(flagCommonName))
	return command
}
