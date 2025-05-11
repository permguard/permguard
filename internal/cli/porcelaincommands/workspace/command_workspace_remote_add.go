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

package workspace

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/workspace"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// commandNameForWorkspacesRemoteAdd is the command name for workspaces remoteadd.
	commandNameForWorkspacesRemoteAdd = "workspaces-remote.add"

	// flagZAP is the flag name for the ZAP port.
	flagZAP = "zap"
	// flagPAP is the flag name for the PAP port.
	flagPAP = "pap"
)

// runECommandForRemoteAddWorkspace runs the command for creating an workspace.
func runECommandForRemoteAddWorkspace(args []string, deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) < 2 {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to add the remote.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliArguments, "failed to add the remote.", err)
			printer.Error(sysErr)
		}
		return common.ErrCommandSilent
	}
	langAbs, err := deps.GetLanguageFactory()
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	wksMgr, err := workspace.NewInternalManager(ctx, langAbs)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	remote := args[0]
	server := args[1]
	zapPort := v.GetInt(options.FlagName(commandNameForWorkspacesRemoteAdd, flagZAP))
	papPort := v.GetInt(options.FlagName(commandNameForWorkspacesRemoteAdd, flagPAP))
	output, err := wksMgr.ExecAddRemote(remote, server, zapPort, papPort, outFunc(ctx, printer))
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to add the remote.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliOperation, "failed to add the remote.", err)
			printer.Error(sysErr)
		}
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceRemoteAdd creates a command for remoteaddializing a permguard workspace.
func CreateCommandForWorkspaceRemoteAdd(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "add",
		Short: `add a new remote ledger to track and interact with`,
		Long: common.BuildCliLongTemplate(`This command adds a new remote ledger to track and interact with.

Examples:
  # add a new remote ledger to track and interact with
  permguard remote add origin 273165098782/magicfarmacia `),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForRemoteAddWorkspace(args, deps, cmd, v)
		},
	}

	command.Flags().Int(flagZAP, 9091, "specify the port number for the ZAP")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesRemoteAdd, flagZAP), command.Flags().Lookup(flagZAP))
	command.Flags().Int(flagPAP, 9092, "specify the port number for the PAP")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesRemoteAdd, flagPAP), command.Flags().Lookup(flagPAP))
	return command
}
