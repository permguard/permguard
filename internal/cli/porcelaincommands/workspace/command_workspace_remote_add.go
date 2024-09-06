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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwksmanager "github.com/permguard/permguard/internal/cli/workspace"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// commandNameForWorkspacesRemoteAdd is the command name for workspaces remoteadd.
	commandNameForWorkspacesRemoteAdd = "workspaces.remote.add"

	flagAAP = "aap"
	flagPAP = "pap"
)

// runECommandForRemoteAddWorkspace runs the command for creating an workspace.
func runECommandForRemoteAddWorkspace(args []string, deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	if len(args) < 2 {
		printer.Error(azerrors.ErrCliArguments)
		return aziclicommon.ErrCommandSilent
	}
	wksMgr := azicliwksmanager.NewInternalManager(ctx)
	remote := args[0]
	server := args[1]
	aapPort := v.GetInt(azconfigs.FlagName(commandNameForWorkspacesRemoteAdd, flagAAP))
	papPort := v.GetInt(azconfigs.FlagName(commandNameForWorkspacesRemoteAdd, flagPAP))
	output, err := wksMgr.ExecAddRemote(remote, server, aapPort, papPort, outFunc(ctx, printer))
	if err != nil {
		printer.Error(err)
		return aziclicommon.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.Print(output)
	}
	return nil
}

// CreateCommandForWorkspaceRemoteAdd creates a command for remoteaddializing a working directory.
func CreateCommandForWorkspaceRemoteAdd(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "add",
		Short: `add a new remote repository to track and interact with`,
		Long: aziclicommon.BuildCliLongTemplate(`This command adds a new remote repository to track and interact with.

Examples:
  # add a new remote repository to track and interact with
  permguard remote add dev 268786704340/magicfarmacia-v0.0 `),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForRemoteAddWorkspace(args, deps, cmd, v)
		},
	}

	command.Flags().Int(flagAAP, 9091, "aap port")
	v.BindPFlag(azconfigs.FlagName(commandNameForWorkspacesRemoteAdd, flagAAP), command.Flags().Lookup(flagAAP))
	command.Flags().Int(flagPAP, 9092, "pap port")
	v.BindPFlag(azconfigs.FlagName(commandNameForWorkspacesRemoteAdd, flagPAP), command.Flags().Lookup(flagPAP))
	return command
}
