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
	// commandNameForIdentitySourcesDelete is the command name for identity sources delete.
	commandNameForIdentitySourcesDelete = "identitysources-delete"
)

// runECommandForDeleteIdentitySource runs the command for creating an identity source.
func runECommandForDeleteIdentitySource(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to delete the identity source.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to delete the identity source")))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcZAPClient(zapTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to delete the identity source.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to delete the identity source")))
		}
		return common.ErrCommandSilent
	}
	zoneID := v.GetInt64(options.FlagName(commandNameForIdentitySource, common.FlagCommonZoneID))
	identitySourceID := v.GetString(options.FlagName(commandNameForIdentitySourcesDelete, flagIdentitySourceID))
	identitySource, err := client.DeleteIdentitySource(zoneID, identitySourceID)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to delete the identity source.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to delete the identity source")))
		}
		return common.ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		identitySourceID := identitySource.IdentitySourceID
		identitySourceName := identitySource.Name
		output[identitySourceID] = identitySourceName
	} else if ctx.IsJSONOutput() {
		output["identity_sources"] = []*zap.IdentitySource{identitySource}
	}
	printer.PrintlnMap(output)
	return nil
}

// createCommandForIdentitySourceDelete creates a command for managing identity sources delete.
func createCommandForIdentitySourceDelete(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "delete",
		Short: "Delete a remote identity source",
		Long: common.BuildCliLongTemplate(`This command deletes a remote identity source.

Examples:
  # delete an identity source and output the result in json format
  permguard authn identitysources delete --zone-id 273165098782 --identitysource-id 1da1d9094501425085859c60429163c2 --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForDeleteIdentitySource(deps, cmd, v)
		},
	}
	command.Flags().String(flagIdentitySourceID, "", "specify the id of the identity source to delete")
	v.BindPFlag(options.FlagName(commandNameForIdentitySourcesDelete, flagIdentitySourceID), command.Flags().Lookup(flagIdentitySourceID))
	return command
}
