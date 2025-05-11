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

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/workspace"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// commandNameForWorkspacesObjects base command name for workspace objects
	commandNameForWorkspacesCat = "workspaces-objects.cat"
	// commandNameForWorkspacesCatRaw shows the raw content of the object
	commandNameForWorkspacesCatRaw = "raw"
	// commandNameForWorkspacesCatContent shows the content of the object
	commandNameForWorkspacesCatContent = "content"
	// commandNameForWorkspacesFrontendLanguage displays the content using the front-end language.
	commandNameForWorkspacesFrontendLanguage = "frontend"
)

// runECommandForObjectsCatWorkspace runs the command for catting the object content.
func runECommandForObjectsCatWorkspace(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, oid string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	absLangFact, err := deps.GetLanguageFactory()
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	wksMgr, err := workspace.NewInternalManager(ctx, absLangFact)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	includeStorage := v.GetBool(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListObjects))
	includeCode := v.GetBool(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListCode))
	if !includeStorage && !includeCode {
		includeStorage = true
	}

	showFrontendLanguage := v.GetBool(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesFrontendLanguage))
	showRaw := v.GetBool(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatRaw))
	showContent := v.GetBool(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatContent))

	output, err := wksMgr.ExecObjectsCat(includeStorage, includeCode, showFrontendLanguage, showRaw, showContent, oid, outFunc(ctx, printer))
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to cat the object.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliOperation, "failed to cat the object.", err)
			printer.Error(sysErr)
		}
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceObjectsCat creates the command for catting the object content.
func CreateCommandForWorkspaceObjectsCat(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "cat",
		Short: "Cat the object content",
		Long: common.BuildCliLongTemplate(`This command cats the object content.

Examples:
  # print the object content
  permguard objects cat 4d5f28519a7e1174ced863971b7db039299ff34560aed145c9f50bbb2481cc0c -p`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForObjectsCatWorkspace(deps, cmd, v, args[0])
		},
		Args: validateArg,
	}

	command.Flags().Bool(commandNameForWorkspacesCatRaw, false, "display the raw, unprocessed content")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatRaw), command.Flags().Lookup(commandNameForWorkspacesCatRaw))

	command.Flags().Bool(commandNameForWorkspacesCatContent, false, "display only the processed content")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatContent), command.Flags().Lookup(commandNameForWorkspacesCatContent))

	command.Flags().Bool(commandNameForWorkspacesFrontendLanguage, false, "display the content formatted using the front-end language")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesFrontendLanguage), command.Flags().Lookup(commandNameForWorkspacesFrontendLanguage))

	return command
}
