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
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	// commandNameForTenant is the command name for tenant.
	commandNameForTenant = "tenant"
	// flagTenantID is the tenant id flag.
	flagTenantID = "tenantid"
)

// runECommandForCreateTenant runs the command for creating a tenant.
func runECommandForUpsertTenant(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
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
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForTenant, aziclicommon.FlagCommonAccountID))
	name := v.GetString(azconfigs.FlagName(flagPrefix, aziclicommon.FlagCommonName))
	tenant := &azmodels.Tenant{
		AccountID: accountID,
		Name:      name,
	}
	if isCreate {
		tenant, err = client.CreateTenant(accountID, name)
	} else {
		tenantID := v.GetString(azconfigs.FlagName(flagPrefix, flagTenantID))
		tenant.TenantID = tenantID
		tenant, err = client.UpdateTenant(tenant)
	}
	if err != nil {
		printer.Error(err)
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		tenantID := tenant.TenantID
		tenantName := tenant.Name
		output[tenantID] = tenantName
	} else if ctx.IsJSONOutput() {
		output["tenants"] = []*azmodels.Tenant{tenant}
	}
	printer.Print(output)
	return nil
}

// runECommandForTenants runs the command for managing tenants.
func runECommandForTenants(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForTenants creates a command for managing tenants.
func createCommandForTenants(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "tenants",
		Short: "Manage remote Tenants",
		Long:  aziclicommon.BuildCliLongTemplate(`This command manages remote tenants.`),
		RunE:  runECommandForTenants,
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForTenant, aziclicommon.FlagCommonAccountID), command.PersistentFlags().Lookup(aziclicommon.FlagCommonAccountID))

	command.AddCommand(createCommandForTenantCreate(deps, v))
	command.AddCommand(createCommandForTenantUpdate(deps, v))
	command.AddCommand(createCommandForTenantDelete(deps, v))
	command.AddCommand(createCommandForTenantList(deps, v))
	return command
}
