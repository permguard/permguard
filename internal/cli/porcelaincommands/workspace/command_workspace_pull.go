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
	// commandNameForWorkspacesPull is the command name for workspaces pull.
	commandNameForWorkspacesPull = "workspaces.pull"
)

// runECommandForPullWorkspace runs the command for creating an workspace.
func runECommandForPullWorkspace(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	_, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	output["workspace"] = "pull"
	printer.Print(output)
	return nil
}

// CreateCommandForWorkspacePull creates a command for pullializing a working directory.
func CreateCommandForWorkspacePull(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pull",
		Short: "Fetch the latest changes from the remote repo and constructs the remote state.",
		Long: aziclicommon.BuildCliLongTemplate(`This command fetches the latest changes from the remote repo and constructs the remote state.

Examples:
  # fetches the latest changes from the remote repo and constructs the remote state
  permguard pull`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPullWorkspace(deps, cmd, v)
		},
	}
	return command
}