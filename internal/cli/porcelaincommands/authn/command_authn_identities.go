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
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelszap "github.com/permguard/permguard/pkg/transport/models/zap"
)

const (
	// commandNameForIdentity is the command name for identity.
	commandNameForIdentity = "identity"
	// flagIdentitySourceID is the flag for identity source id.
	flagIdentityID = "identity-id"
	// flagIdentitySourceID is the flag for identity source id.
	flagIdentityKind = "kind"
)

// runECommandForCreateIdentity runs the command for creating an identity.
func runECommandForUpsertIdentity(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	opGetErroMessage := func(op bool) string {
		if op {
			return "Failed to create the identity"
		}
		return "Failed to upsert the identity"
	}
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, strings.ToLower(opGetErroMessage(isCreate)), err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, strings.ToLower(opGetErroMessage(isCreate)), err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	zoneID := v.GetInt64(azoptions.FlagName(commandNameForIdentity, aziclicommon.FlagCommonZoneID))
	name := v.GetString(azoptions.FlagName(flagPrefix, aziclicommon.FlagCommonName))
	kind := v.GetString(azoptions.FlagName(flagPrefix, flagIdentityKind))
	identity := &azmodelszap.Identity{
		ZoneID: zoneID,
		Kind:   kind,
		Name:   name,
	}
	if isCreate {
		identitySourceID := v.GetString(azoptions.FlagName(flagPrefix, flagIdentitySourceID))
		identity, err = client.CreateIdentity(zoneID, identitySourceID, kind, name)
	} else {
		identityID := v.GetString(azoptions.FlagName(flagPrefix, flagIdentityID))
		identity.IdentityID = identityID
		identity, err = client.UpdateIdentity(identity)
	}
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println(fmt.Sprintf("%s.", opGetErroMessage(isCreate)))
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliOperation, strings.ToLower(opGetErroMessage(isCreate)), err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		identityID := identity.IdentityID
		identityName := identity.Name
		output[identityID] = identityName
	} else if ctx.IsJSONOutput() {
		output["identities"] = []*azmodelszap.Identity{identity}
	}
	printer.PrintlnMap(output)
	return nil
}

// runECommandForIdentities runs the command for managing identities.
func runECommandForIdentities(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForIdentities creates a command for managing identities.
func createCommandForIdentities(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "identities",
		Short: "Manage remote identities",
		Long:  aziclicommon.BuildCliLongTemplate(`This command manages remote identities.`),
		RunE:  runECommandForIdentities,
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonZoneID, 0, "zone id")
	v.BindPFlag(azoptions.FlagName(commandNameForIdentity, aziclicommon.FlagCommonZoneID), command.PersistentFlags().Lookup(aziclicommon.FlagCommonZoneID))

	command.AddCommand(createCommandForIdentityCreate(deps, v))
	command.AddCommand(createCommandForIdentityUpdate(deps, v))
	command.AddCommand(createCommandForIdentityDelete(deps, v))
	command.AddCommand(createCommandForIdentityList(deps, v))
	return command
}
