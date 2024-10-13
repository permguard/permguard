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
	azcli "github.com/permguard/permguard/pkg/cli"
)

const (
	// commandNameForWorkspacesClone is the command name for workspaces clone.
	commandNameForWorkspacesClone = "workspaces.clone"
)

// runECommandForCloneWorkspace runs the command for creating an workspace.
func runECommandForCloneWorkspace(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	_, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	output["workspace"] = "clone"
	printer.Println(output)
	return nil
}

// CreateCommandForWorkspaceClone creates a command for cloneializing a working directory.
func CreateCommandForWorkspaceClone(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "clone",
		Short: "Clone a remote repository to the local working directory",
		Long: aziclicommon.BuildCliLongTemplate(`This command clones a remote repository to the local working directory.

Examples:
  # clone a remote repository to the local working directory
  permguard clone 268786704340/magicfarmacia-v0.0`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCloneWorkspace(deps, cmd, v)
		},
	}
	return command
}
