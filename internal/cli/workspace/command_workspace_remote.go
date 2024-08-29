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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
)

const (
	// commandNameForWorkspacesRemote is the command name for workspaces remote.
	commandNameForWorkspacesRemote = "workspaces.remote"
)

// runECommandForRemoteWorkspace runs the command for creating an workspace.
func runECommandForRemoteWorkspace(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// CreateCommandForWorkspaceRemote creates a command for remoteializing a working directory.
func CreateCommandForWorkspaceRemote(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "remote",
		Short: `Manage the set of repos ("remotes") whose PermGuard servers you track`,
		Long: aziclicommon.BuildCliLongTemplate(`This command manages the set of repos ("remotes") whose PermGuard servers you track.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForRemoteWorkspace(cmd, args)
		},
	}
	command.AddCommand(CreateCommandForWorkspaceRemoteAdd(deps, v))
	command.AddCommand(CreateCommandForWorkspaceRemoteRemove(deps, v))
	command.AddCommand(CreateCommandForWorkspaceRemoteSetdefault(deps, v))
	return command
}
