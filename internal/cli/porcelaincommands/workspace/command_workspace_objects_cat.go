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
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForWorkspacesObjects base command name for workspace objects
	commandNameForWorkspacesCat = "workspaces-objects.cat"
	// commandNameForWorkspacesCatRaw shows the raw content of the object
	commandNameForWorkspacesCatRaw = "raw"
	// commandNameForWorkspacesCatContent shows the content of the object
	commandNameForWorkspacesCatContent = "content"
	// commandNameForWorkspacesHuman displays the content in human-readable format.
	commandNameForWorkspacesHuman = "human"
	// commandNameForWorkspacesCatInspect displays all object fields as an aligned tabular inspect view.
	commandNameForWorkspacesCatInspect = "inspect"
)

// runECommandForObjectsCatWorkspace runs the command for catting the object content.
func runECommandForObjectsCatWorkspace(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper, oid string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	absLangFact, err := deps.LanguageFactory()
	if err != nil {
		return failWithDetails(ctx, printer, err)
	}
	wksMgr, err := workspace.NewInternalManager(ctx, absLangFact)
	if err != nil {
		return failWithDetails(ctx, printer, err)
	}
	includeStorage := v.GetBool(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListObjects))
	includeCode := v.GetBool(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListCode))
	if !includeStorage && !includeCode {
		includeStorage = true
	}

	showHuman := v.GetBool(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesHuman))
	showRaw := v.GetBool(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatRaw))
	showContent := v.GetBool(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatContent))
	showInspect := v.GetBool(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatInspect))

	output, err := wksMgr.ExecObjectsCat(includeStorage, includeCode, showHuman, showRaw, showContent, showInspect, oid, outFunc(ctx, printer))
	if err != nil {
		printer.ErrorWithOutput(finalizeErrorOutput(ctx, output), errors.Join(errors.New("cli: failed to cat the object"), err))
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(finalizeOutput(ctx, output))
	}
	return nil
}

// CreateCommandForWorkspaceObjectsCat creates the command for catting the object content.
func CreateCommandForWorkspaceObjectsCat(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "cat",
		Short: "Cat the object content",
		Long: common.BuildCliLongTemplate(`This command cats the object content.

Examples:
  # print the object content
  permguard objects cat bafyreihpc3vupfos5yqnlakgbrpjx3ztbkwwlir5zetbwo3y6uhzpwtxuy --human

  # inspect all object fields in a tabular view
  permguard objects cat bafyreihpc3vupfos5yqnlakgbrpjx3ztbkwwlir5zetbwo3y6uhzpwtxuy --inspect`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForObjectsCatWorkspace(deps, cmd, v, args[0])
		},
		Args: validateArg,
	}

	command.Flags().Bool(commandNameForWorkspacesCatRaw, false, "display the raw, unprocessed content")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatRaw), command.Flags().Lookup(commandNameForWorkspacesCatRaw))

	command.Flags().Bool(commandNameForWorkspacesCatContent, false, "display only the processed content")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatContent), command.Flags().Lookup(commandNameForWorkspacesCatContent))

	command.Flags().Bool(commandNameForWorkspacesHuman, false, "display the content in human-readable format")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesHuman), command.Flags().Lookup(commandNameForWorkspacesHuman))

	command.Flags().Bool(commandNameForWorkspacesCatInspect, false, "display all object fields as a raw tabular inspect view")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspacesCat, commandNameForWorkspacesCatInspect), command.Flags().Lookup(commandNameForWorkspacesCatInspect))

	return command
}
