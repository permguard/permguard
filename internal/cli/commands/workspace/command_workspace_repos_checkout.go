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

	aziclicommon "github.com/permguard/permguard/internal/cli/commands/common"
	azcli "github.com/permguard/permguard/pkg/cli"
)

const (
	// commandNameForWorkspacesRepoCheckout is the command name for workspaces repocheckout.
	commandNameForWorkspacesRepoCheckout = "workspaces.repo.checkout"
)

// runECommandForRepoCheckoutWorkspace runs the command for creating an workspace.
func runECommandForRepoCheckoutWorkspace(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	_, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(aziclicommon.ErrorMessageCliBug)
		return aziclicommon.ErrCommandSilent
	}
	output := map[string]any{}
	output["workspace"] = "repos-checkout"
	printer.Print(output)
	return nil
}

// CreateCommandForWorkspaceRepoCheckout creates a command for repocheckoutializing a working directory.
func CreateCommandForWorkspaceRepoCheckout(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "checkout",
		Short: `Checkout a repo`,
		Long: aziclicommon.BuildCliLongTemplate(`This command checkouts a repo.

Examples:
  # checkout a new repo
  ❯ permguard repo checkout dev/268786704340/magicfarmacia-v0.0 `),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForRepoCheckoutWorkspace(deps, cmd, v)
		},
	}
	return command
}
