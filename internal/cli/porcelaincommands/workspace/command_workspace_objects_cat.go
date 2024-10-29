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
	// commandNameForWorkspacesObjectsCat is the command to cat the object content.
	commandNameForWorkspacesObjectsCat = "workspaces.objects.cat"
)

// runECommandForObjectsCatWorkspace runs the command for catting the object content.
func runECommandForObjectsCatWorkspace(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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

// CreateCommandForWorkspaceObjectsCat creates the command for catting the object content.
func CreateCommandForWorkspaceObjectsCat(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "cat",
		Short: "Cat the object content",
		Long: aziclicommon.BuildCliLongTemplate(`This command cats the object content.

Examples:
  # cat the object content
  permguard objects cat 4d5f28519a7e1174ced863971b7db039299ff34560aed145c9f50bbb2481cc0c`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForObjectsCatWorkspace(deps, cmd, v)
		},
	}
	return command
}
