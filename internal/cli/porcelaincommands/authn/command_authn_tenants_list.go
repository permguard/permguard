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
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForTenantsList is the command name for tenants list.
	commandNameForTenantsList = "tenants-list"
)

// runECommandForListTenants runs the command for creating a tenant.
func runECommandForListTenants(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list tenants.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list tenants")))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list tenants.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list tenants")))
		}
		return common.ErrCommandSilent
	}
	page := v.GetInt32(options.FlagName(commandNameForTenantsList, common.FlagCommonPage))
	pageSize := v.GetInt32(options.FlagName(commandNameForTenantsList, common.FlagCommonPageSize))
	zoneID := v.GetInt64(options.FlagName(commandNameForTenant, common.FlagCommonZoneID))
	tenantID := v.GetString(options.FlagName(commandNameForTenantsList, flagTenantID))
	name := v.GetString(options.FlagName(commandNameForTenantsList, common.FlagCommonName))
	tenants, err := client.FetchTenantsBy(page, pageSize, zoneID, tenantID, name)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list tenants.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list tenants")))
		}
		return common.ErrCommandSilent
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
func createCommandForTenantList(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List remote tenants",
		Long: common.BuildCliLongTemplate(`This command lists all remote tenants.

Examples:
  # list all tenants amd output in json format
  permguard authn tenants list --zone-id 273165098782
  # lista all tenants and filter by name
  permguard authn tenants list --zone-id 273165098782 --name matera
  # list all tenants and filter by tenant id
  permguard authn tenants list --zone-id 273165098782 --tenant-id 2e190ee712494838bb54d67e2a0c496a
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListTenants(deps, cmd, v)
		},
	}
	command.Flags().Int32P(common.FlagCommonPage, common.FlagCommonPageShort, 1, "specify the page number for paginated results")
	v.BindPFlag(options.FlagName(commandNameForTenantsList, common.FlagCommonPage), command.Flags().Lookup(common.FlagCommonPage))
	command.Flags().Int32P(common.FlagCommonPageSize, common.FlagCommonPageSizeShort, 1000, "specify the number of results per page")
	v.BindPFlag(options.FlagName(commandNameForTenantsList, common.FlagCommonPageSize), command.Flags().Lookup(common.FlagCommonPageSize))
	command.Flags().String(flagTenantID, "", "filter results by tenant id")
	v.BindPFlag(options.FlagName(commandNameForTenantsList, flagTenantID), command.Flags().Lookup(flagTenantID))
	command.Flags().String(common.FlagCommonName, "", "filter results by tenant name")
	v.BindPFlag(options.FlagName(commandNameForTenantsList, common.FlagCommonName), command.Flags().Lookup(common.FlagCommonName))
	return command
}
