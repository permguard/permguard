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
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
)

const (
	// commandNameForWorkspacesPlan is the command name for workspaces plan.
	commandNameForWorkspacesPlan = "workspaces.plan"
)

// runECommandForPlanWorkspace runs the command for creating an workspace.
func runECommandForPlanWorkspace(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	_, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(aziclicommon.ErrorMessageCliBug)
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	output["workspace"] = "plan"
	printer.Print(output)
	return nil
}

// CreateCommandForWorkspacePlan creates a command for planializing a working directory.
func CreateCommandForWorkspacePlan(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "plan",
		Short: "Plan the difference between the working directory and a remote repo to be applied",
		Long: aziclicommon.BuildCliLongTemplate(`This command plans the difference between the working directory and a remote repo to be applied.

Examples:
  # plan the difference between the working directory and a remote repo to be applied
  permguard plan`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPlanWorkspace(deps, cmd, v)
		},
	}
	return command
}
