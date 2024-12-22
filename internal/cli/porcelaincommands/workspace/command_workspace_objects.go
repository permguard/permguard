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
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForWorkspacesObjects base command name for workspace objects
	commandNameForWorkspacesObjects = "workspaces.objects.list"
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
func runECommandForObjectsWorkspace(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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

	includeStorage := v.GetBool(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListObjects))
	includeCode := v.GetBool(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListCode))
	if !includeStorage && !includeCode {
		includeStorage = true
	}

	filterCommits := v.GetBool(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListCommit))
	filterTrees := v.GetBool(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListTree))
	filterBlob := v.GetBool(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListBlob))
	filterAll := v.GetBool(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListAll))
	if filterAll {
		filterCommits, filterTrees, filterBlob = true, true, true
	} else if !filterCommits && !filterTrees && !filterBlob {
		filterCommits = true
	}

	output, err := wksMgr.ExecObjects(includeStorage, includeCode, filterCommits, filterTrees, filterBlob, outFunc(ctx, printer))
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

// CreateCommandForWorkspaceObjects creates a command for diffializing a permguard workspace.
func CreateCommandForWorkspaceObjects(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "objects",
		Short: "Manage the object store",
		Long: aziclicommon.BuildCliLongTemplate(`This command manages the object store.

Examples:
  # list the objects in the workspace
  permguard objects`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForObjectsWorkspace(deps, cmd, v)
		},
	}

	command.PersistentFlags().Bool(commandNameForWorkspacesObjectsListObjects, false, "include objects from the object store in the results")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListObjects), command.PersistentFlags().Lookup(commandNameForWorkspacesObjectsListObjects))

	command.PersistentFlags().Bool(commandNameForWorkspacesObjectsListCode, false, "include objects from the code store in the results")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListCode), command.PersistentFlags().Lookup(commandNameForWorkspacesObjectsListCode))

	command.Flags().Bool(commandNameForWorkspacesObjectsListCommit, false, "filter results to include only objects of type 'commit'")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListCommit), command.Flags().Lookup(commandNameForWorkspacesObjectsListCommit))

	command.Flags().Bool(commandNameForWorkspacesObjectsListTree, false, "filter results to include only objects of type 'tree'")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListTree), command.Flags().Lookup(commandNameForWorkspacesObjectsListTree))

	command.Flags().Bool(commandNameForWorkspacesObjectsListBlob, false, "filter results to include only objects of type 'blob'")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListBlob), command.Flags().Lookup(commandNameForWorkspacesObjectsListBlob))

	command.Flags().Bool(commandNameForWorkspacesObjectsListAll, false, "include all object types in the results")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspacesObjects, commandNameForWorkspacesObjectsListAll), command.Flags().Lookup(commandNameForWorkspacesObjectsListAll))

	command.AddCommand(CreateCommandForWorkspaceObjectsCat(deps, v))
	return command
}
