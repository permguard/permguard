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
	azmodels "github.com/permguard/permguard/pkg/transport/models"
)

const (
	// commandNameForTenant is the command name for tenant.
	commandNameForTenantsDelete = "tenants.delete"
)

// runECommandForDeleteTenant runs the command for creating a tenant.
func runECommandForDeleteTenant(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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
	applicationID := v.GetInt64(azoptions.FlagName(commandNameForTenant, aziclicommon.FlagCommonApplicationID))
	tenantID := v.GetString(azoptions.FlagName(commandNameForTenantsDelete, flagTenantID))
	tenant, err := client.DeleteTenant(applicationID, tenantID)
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed to delete the tenant.")
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		tenantID := tenant.TenantID
		tenantName := tenant.Name
		output[tenantID] = tenantName
	} else if ctx.IsJSONOutput() {
		output["tenant"] = []*azmodels.Tenant{tenant}
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForTenantDelete creates a command for managing tenantdelete.
func createCommandForTenantDelete(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a remote tenant",
		Long: aziclicommon.BuildCliLongTemplate(`This command deletes a remote tenant.

Examples:
  # delete a tenant and output the result in json format
  permguard authn tenants delete --appid 268786704340 --tenantid 2e190ee712494838bb54d67e2a0c496a
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteTenant(deps, cmd, v)
		},
	}
	command.Flags().String(flagTenantID, "", "specify the ID of the tenant to delete")
	v.BindPFlag(azoptions.FlagName(commandNameForTenantsDelete, flagTenantID), command.Flags().Lookup(flagTenantID))
	return command
}
