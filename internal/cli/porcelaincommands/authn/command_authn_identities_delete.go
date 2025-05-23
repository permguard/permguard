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
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

const (
	// commandNameForIdentity is the command name for identity.
	commandNameForIdentitiesDelete = "identities-delete"
)

// runECommandForDeleteIdentity runs the command for creating an identity.
func runECommandForDeleteIdentity(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to delete the identity.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to delete the identity")))
		}
		return common.ErrCommandSilent
	}

	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to delete the identity.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to delete the identity")))
		}
		return common.ErrCommandSilent
	}
	zoneID := v.GetInt64(options.FlagName(commandNameForIdentity, common.FlagCommonZoneID))
	identityID := v.GetString(options.FlagName(commandNameForIdentitiesDelete, flagIdentityID))
	identity, err := client.DeleteIdentity(zoneID, identityID)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to delete the identity.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to delete the identity")))
		}
		return common.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		identityID := identity.IdentityID
		identityName := identity.Name
		output[identityID] = identityName
	} else if ctx.IsJSONOutput() {
		output["identities"] = []*zap.Identity{identity}
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForIdentityDelete creates a command for managing identitydelete.
func createCommandForIdentityDelete(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a remote identity",
		Long: common.BuildCliLongTemplate(`This command deletes a remote identity.

Examples:
  # delete an identity and output the result in json format
  permguard authn identities delete --zone-id 273165098782 --identity-id 1da1d9094501425085859c60429163c2 --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteIdentity(deps, cmd, v)
		},
	}
	command.Flags().String(flagIdentityID, "", "specify the id of the identity to delete")
	v.BindPFlag(options.FlagName(commandNameForIdentitiesDelete, flagIdentityID), command.Flags().Lookup(flagIdentityID))
	return command
}
