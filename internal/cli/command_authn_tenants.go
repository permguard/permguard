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

	aziclients "github.com/permguard/permguard/internal/agents/clients"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForTenant = "tenant"
	flagTenantID         = "tenantid"
)

// runECommandForCreateTenant runs the command for creating a tenant.
func runECommandForUpsertTenant(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	ctx, printer, err := deps.CreateContextAndPrinter(cmd, v)
	if err != nil {
		color.Red(errorMessageCliBug)
		return ErrCommandSilent
	}
	aapTarget := ctx.GetAAPTarget()
	client, err := aziclients.NewGrpcAAPClient(aapTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid aap target %s", aapTarget))
		return ErrCommandSilent
	}
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForTenant, flagCommonAccountID))
	name := v.GetString(azconfigs.FlagName(flagPrefix, flagCommonName))
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
		return ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		tenantID := tenant.TenantID
		tenantName := tenant.Name
		output[tenantID] = tenantName
	} else if ctx.IsJSONOutput() {
		output["tenant"] = []*azmodels.Tenant{tenant}
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
		Short: "Manage Tenants",
		Long:  fmt.Sprintf(cliLongTemplate, `This command manages tenants.`),
		RunE:  runECommandForTenants,
	}

	command.PersistentFlags().Int64(flagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForTenant, flagCommonAccountID), command.PersistentFlags().Lookup(flagCommonAccountID))

	command.AddCommand(createCommandForTenantCreate(deps, v))
	command.AddCommand(createCommandForTenantUpdate(deps, v))
	command.AddCommand(createCommandForTenantDelete(deps, v))
	command.AddCommand(createCommandForTenantList(deps, v))
	return command
}
