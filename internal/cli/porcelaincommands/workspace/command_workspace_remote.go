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

// runECommandForRemoteWorkspace runs the command for creating an workspace.
func runECommandForRemoteWorkspace(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
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
	output, err := wksMgr.ExecListRemotes(outFunc(ctx, printer))
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list remotes.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to list remote"), err))
		}
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceRemote creates a command for remoteializing a permguard workspace.
func CreateCommandForWorkspaceRemote(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "remote",
		Short: `Manage remote server for tracking and interaction`,
		Long:  common.BuildCliLongTemplate(`This command manages remote server for tracking and interaction`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForRemoteWorkspace(deps, cmd, v)
		},
	}
	command.AddCommand(CreateCommandForWorkspaceRemoteAdd(deps, v))
	command.AddCommand(CreateCommandForWorkspaceRemoteRemove(deps, v))
	return command
}
