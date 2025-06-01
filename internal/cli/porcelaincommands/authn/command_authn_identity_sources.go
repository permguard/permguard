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
	// commandNameForIdentitySource is the command name for identity source.
	commandNameForIdentitySource = "identitysource"
	// flagIdentitySourceID is the flag for identity source id.
	flagIdentitySourceID = "identitysource-id"
)

// runECommandForCreateIdentitySource runs the command for creating an identity source.
func runECommandForUpsertIdentitySource(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	opGetErroMessage := func(op bool) string {
		if op {
			return "Failed to create the identity source"
		}
		return "Failed to upsert the identity source"
	}
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapTarget, err := ctx.ZAPTarget()
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
	zoneID := v.GetInt64(options.FlagName(commandNameForIdentitySource, common.FlagCommonZoneID))
	name := v.GetString(options.FlagName(flagPrefix, common.FlagCommonName))
	identitySource := &zap.IdentitySource{
		ZoneID: zoneID,
		Name:   name,
	}
	if isCreate {
		identitySource, err = client.CreateIdentitySource(zoneID, name)
	} else {
		identitySourceID := v.GetString(options.FlagName(flagPrefix, flagIdentitySourceID))
		identitySource.IdentitySourceID = identitySourceID
		identitySource, err = client.UpdateIdentitySource(identitySource)
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
		identitySourceID := identitySource.IdentitySourceID
		identitieSourceName := identitySource.Name
		output[identitySourceID] = identitieSourceName
	} else if ctx.IsJSONOutput() {
		output["identity_sources"] = []*zap.IdentitySource{identitySource}
	}
	printer.PrintlnMap(output)
	return nil
}

// runECommandForIdentitySources runs the command for managing identity sources.
func runECommandForIdentitySources(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForIdentitySources creates a command for managing identity sources.
func createCommandForIdentitySources(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "identitysources",
		Short: "Manage remote identity sources",
		Long:  common.BuildCliLongTemplate(`This command manages remote identity sources.`),
		RunE:  runECommandForIdentitySources,
	}

	command.PersistentFlags().Int64(common.FlagCommonZoneID, 0, "zone id")
	v.BindPFlag(options.FlagName(commandNameForIdentitySource, common.FlagCommonZoneID), command.PersistentFlags().Lookup(common.FlagCommonZoneID))

	command.AddCommand(createCommandForIdentitySourceCreate(deps, v))
	command.AddCommand(createCommandForIdentitySourceUpdate(deps, v))
	command.AddCommand(createCommandForIdentitySourceDelete(deps, v))
	command.AddCommand(createCommandForIdentitySourceList(deps, v))
	return command
}
