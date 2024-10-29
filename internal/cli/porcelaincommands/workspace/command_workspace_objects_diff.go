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
)

const (
	// commandNameForWorkspacesObjectsDiff is the command to diff the object content.
	commandNameForWorkspacesObjectsDiff = "workspaces.objects.diff"
)

// runECommandForObjectsDiffWorkspace runs the command for diffting the object content.
func runECommandForObjectsDiffWorkspace(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	absLang, err := deps.GetLanguageFactory()
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	wksMgr, err := azicliwksmanager.NewInternalManager(ctx, absLang)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	output, err := wksMgr.ExecObjects(outFunc(ctx, printer))
	if err != nil {
		if ctx.IsJSONOutput() {
			printer.ErrorWithOutput(output, err)
		} else if ctx.IsTerminalOutput() {
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceObjectsDiff command to perform a differential analysis on objects content.
func CreateCommandForWorkspaceObjectsDiff(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "diff",
		Short: "Diff the objects content",
		Long: aziclicommon.BuildCliLongTemplate(`This command performs a differential analysis on objects content.

Examples:
  # perform a differential analysis on objects content
  permguard objects diff 4d5f28519a7e1174ced863971b7db039299ff34560aed145c9f50bbb2481cc0c 88ce0046ca1db14211370a82de5be974f2a8744c825d8901586c0d9b0ae85748`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForObjectsDiffWorkspace(deps, cmd, v)
		},
	}
	return command
}
