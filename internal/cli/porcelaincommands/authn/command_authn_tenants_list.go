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
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForTenantsList is the command name for tenants list.
	commandNameForTenantsList = "tenants.list"
)

// runECommandForListTenants runs the command for creating a tenant.
func runECommandForListTenants(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := deps.CreateGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return aziclicommon.ErrCommandSilent
	}
	page := v.GetInt32(azoptions.FlagName(commandNameForTenantsList, aziclicommon.FlagCommonPage))
	pageSize := v.GetInt32(azoptions.FlagName(commandNameForTenantsList, aziclicommon.FlagCommonPageSize))
	applicationID := v.GetInt64(azoptions.FlagName(commandNameForTenant, aziclicommon.FlagCommonApplicationID))
	tenantID := v.GetString(azoptions.FlagName(commandNameForTenantsList, flagTenantID))
	name := v.GetString(azoptions.FlagName(commandNameForTenantsList, aziclicommon.FlagCommonName))
	tenants, err := client.FetchTenantsBy(page, pageSize, applicationID, tenantID, name)
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed to list tenants.")
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
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
	printer.PrintlnMap(output)
	return nil
}

// createCommandForTenantList creates a command for managing tenantlist.
func createCommandForTenantList(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote tenants",
		Long: aziclicommon.BuildCliLongTemplate(`This command lists all remote tenants.

Examples:
  # list all tenants amd output in json format
  permguard authn tenants list --appid 268786704340
  # lista all tenants and filter by name
  permguard authn tenants list --appid 268786704340 --name matera
  # list all tenants and filter by tenant id
  permguard authn tenants list --appid 268786704340 --tenantid 2e190ee712494838bb54d67e2a0c496a
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListTenants(deps, cmd, v)
		},
	}
	command.Flags().Int32P(aziclicommon.FlagCommonPage, aziclicommon.FlagCommonPageShort, 1, "specify the page number for paginated results")
	v.BindPFlag(azoptions.FlagName(commandNameForTenantsList, aziclicommon.FlagCommonPage), command.Flags().Lookup(aziclicommon.FlagCommonPage))
	command.Flags().Int32P(aziclicommon.FlagCommonPageSize, aziclicommon.FlagCommonPageSizeShort, 1000, "specify the number of results per page")
	v.BindPFlag(azoptions.FlagName(commandNameForTenantsList, aziclicommon.FlagCommonPageSize), command.Flags().Lookup(aziclicommon.FlagCommonPageSize))
	command.Flags().String(flagTenantID, "", "filter results by tenant id")
	v.BindPFlag(azoptions.FlagName(commandNameForTenantsList, flagTenantID), command.Flags().Lookup(flagTenantID))
	command.Flags().String(aziclicommon.FlagCommonName, "", "filter results by tenant name")
	v.BindPFlag(azoptions.FlagName(commandNameForTenantsList, aziclicommon.FlagCommonName), command.Flags().Lookup(aziclicommon.FlagCommonName))
	return command
}
