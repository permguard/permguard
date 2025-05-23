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
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

const (
	// commandNameForTenant is the command name for tenant.
	commandNameForTenant = "tenant"
	// flagTenantID is the tenant id flag.
	flagTenantID = "tenant-id"
)

// runECommandForCreateTenant runs the command for creating a tenant.
func runECommandForUpsertTenant(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	opGetErroMessage := func(op bool) string {
		if op {
			return "Failed to create the tenant"
		}
		return "Failed to upsert the tenant"
	}
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New(strings.ToLower(opGetErroMessage(isCreate)))))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New(strings.ToLower(opGetErroMessage(isCreate)))))
		}
		return common.ErrCommandSilent
	}
	zoneID := v.GetInt64(options.FlagName(commandNameForTenant, common.FlagCommonZoneID))
	name := v.GetString(options.FlagName(flagPrefix, common.FlagCommonName))
	tenant := &zap.Tenant{
		ZoneID: zoneID,
		Name:   name,
	}
	if isCreate {
		tenant, err = client.CreateTenant(zoneID, name)
	} else {
		tenantID := v.GetString(options.FlagName(flagPrefix, flagTenantID))
		tenant.TenantID = tenantID
		tenant, err = client.UpdateTenant(tenant)
	}
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New(strings.ToLower(opGetErroMessage(isCreate)))))
		}
		return common.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		tenantID := tenant.TenantID
		tenantName := tenant.Name
		output[tenantID] = tenantName
	} else if ctx.IsJSONOutput() {
		output["tenants"] = []*zap.Tenant{tenant}
	}
	printer.PrintlnMap(output)
	return nil
}

// runECommandForTenants runs the command for managing tenants.
func runECommandForTenants(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForTenants creates a command for managing tenants.
func createCommandForTenants(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "tenants",
		Short: "Manage remote Tenants",
		Long:  common.BuildCliLongTemplate(`This command manages remote tenants.`),
		RunE:  runECommandForTenants,
	}

	command.PersistentFlags().Int64(common.FlagCommonZoneID, 0, "zone id")
	v.BindPFlag(options.FlagName(commandNameForTenant, common.FlagCommonZoneID), command.PersistentFlags().Lookup(common.FlagCommonZoneID))

	command.AddCommand(createCommandForTenantCreate(deps, v))
	command.AddCommand(createCommandForTenantUpdate(deps, v))
	command.AddCommand(createCommandForTenantDelete(deps, v))
	command.AddCommand(createCommandForTenantList(deps, v))
	return command
}
