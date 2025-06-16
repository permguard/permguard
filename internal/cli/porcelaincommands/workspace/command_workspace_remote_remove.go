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
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/workspace"
	"github.com/permguard/permguard/pkg/cli"
)

const (
	// commandNameForWorkspacesRemoteRemove is the command name for workspaces remoteremove.
	commandNameForWorkspacesRemoteRemove = "workspaces-remote.remove"
)

// runECommandForRemoteRemoveWorkspace runs the command for creating an workspace.
func runECommandForRemoteRemoveWorkspace(args []string, deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) < 1 {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to remove the remote.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to remove the remote")))
		}
		return common.ErrCommandSilent
	}
	langAbs, err := deps.LanguageFactory()
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
	output, err := wksMgr.ExecRemoveRemote(remote, outFunc(ctx, printer))
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to remove the remote.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to remove the remote")))
		}
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceRemoteRemove creates a command for remoteremoveializing a permguard workspace.
func CreateCommandForWorkspaceRemoteRemove(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "remove",
		Short: `remove a remote ledger from the configuration`,
		Long: common.BuildCliLongTemplate(`This command removes a remote ledger from the configuration.

Examples:
  # remove a remote ledger from the configuration
  permguard remote remove origin`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForRemoteRemoveWorkspace(args, deps, cmd, v)
		},
	}
	return command
}
