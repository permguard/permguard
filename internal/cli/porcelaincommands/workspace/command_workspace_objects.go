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
	commandNameForWorkspacesObjects = "workspaces-objects.list"
	// commandNameForWorkspacesObjectsListObjects lists objects from the object store
	commandNameForWorkspacesObjectsListObjects = "objects"
	// commandNameForWorkspacesObjectsListCode lists objects from the code store
	commandNameForWorkspacesObjectsListCode = "code"

	// commandNameForWorkspacesObjectsListCommit lists objects of commit type
	commandNameForWorkspacesObjectsListCommit = "commit"
	// commandNameForWorkspacesObjectsListTree lists objects of tree type
	commandNameForWorkspacesObjectsListTree = "tree"
	// commandNameForWorkspacesObjectsListTree lists objects of blob type
	commandNameForWorkspacesObjectsListBlob = "blob"
	// commandNameForWorkspacesObjectsListAll lists objects of all types
	commandNameForWorkspacesObjectsListAll = "all"
)

// runECommandForObjectsWorkspace run the command for listing objects in the workspace.
func runECommandForObjectsWorkspace(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	absLangFact, err := deps.LanguageFactory()
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

	filterCommits := v.GetBool(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListCommit))
	filterTrees := v.GetBool(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListTree))
	filterBlob := v.GetBool(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListBlob))
	filterAll := v.GetBool(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListAll))
	if filterAll {
		filterCommits, filterTrees, filterBlob = true, true, true
	} else if !filterCommits && !filterTrees && !filterBlob {
		filterCommits = true
	}

	output, err := wksMgr.ExecObjects(includeStorage, includeCode, filterCommits, filterTrees, filterBlob, outFunc(ctx, printer))
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to list objects.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to list objects")))
		}
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceObjects creates a command for diffializing a permguard workspace.
func CreateCommandForWorkspaceObjects(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "objects",
		Short: "Manage the object store",
		Long: common.BuildCliLongTemplate(`This command manages the object store.

Examples:
  # list the objects in the workspace
  permguard objects`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForObjectsWorkspace(deps, cmd, v)
		},
	}

	command.PersistentFlags().Bool(commandNameForWorkspacesObjectsListObjects, false, "include objects from the object store in the results")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListObjects), command.PersistentFlags().Lookup(commandNameForWorkspacesObjectsListObjects))

	command.PersistentFlags().Bool(commandNameForWorkspacesObjectsListCode, false, "include objects from the code store in the results")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListCode), command.PersistentFlags().Lookup(commandNameForWorkspacesObjectsListCode))

	command.Flags().Bool(commandNameForWorkspacesObjectsListCommit, false, "filter results to include only objects of type 'commit'")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListCommit), command.Flags().Lookup(commandNameForWorkspacesObjectsListCommit))

	command.Flags().Bool(commandNameForWorkspacesObjectsListTree, false, "filter results to include only objects of type 'tree'")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListTree), command.Flags().Lookup(commandNameForWorkspacesObjectsListTree))

	command.Flags().Bool(commandNameForWorkspacesObjectsListBlob, false, "filter results to include only objects of type 'blob'")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListBlob), command.Flags().Lookup(commandNameForWorkspacesObjectsListBlob))

	command.Flags().Bool(commandNameForWorkspacesObjectsListAll, false, "include all object types in the results")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListAll), command.Flags().Lookup(commandNameForWorkspacesObjectsListAll))

	command.AddCommand(CreateCommandForWorkspaceObjectsCat(deps, v))
	return command
}
