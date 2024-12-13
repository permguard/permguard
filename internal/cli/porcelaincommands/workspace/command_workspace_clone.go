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
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azfiles "github.com/permguard/permguard-core/pkg/extensions/files"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwksmanager "github.com/permguard/permguard/internal/cli/workspace"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azplangcedar "github.com/permguard/permguard/plugin/languages/cedar"
)

const (
	// commandNameForWorkspacesClone is the command name for workspaces clone.
	commandNameForWorkspacesClone = "workspaces.clone"
)

// runECommandForCloneWorkspace runs the command for creating an workspace.
func runECommandForCloneWorkspace(args []string, deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	if len(args) < 1 {
		color.Red("Invalid arguments")
		return aziclicommon.ErrCommandSilent
	}
	repoURI := strings.ToLower(args[0])
	if !strings.HasPrefix(repoURI, "permguard@") {
		color.Red("Invalid arguments")
		return aziclicommon.ErrCommandSilent
	}
	repo := strings.TrimPrefix(repoURI, "permguard@")
	elements := strings.Split(repo, "/")
	if len(elements) < 3 {
		color.Red("Invalid arguments")
		return aziclicommon.ErrCommandSilent
	}
	folder := elements[2]
	workDir, err := cmd.Flags().GetString(aziclicommon.FlagWorkingDirectory)
	repoFolder := filepath.Join(workDir, folder)
	cmd.Flags().Set(aziclicommon.FlagWorkingDirectory, repoFolder)
	if ok, _ := azfiles.CheckPathIfExists(repoFolder); ok {
		color.Red(fmt.Sprintf("The repository %s already exists", repoFolder))
		return aziclicommon.ErrCommandSilent
	}
	azfiles.CreateDirIfNotExists(repoFolder)

	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	if len(args) < 1 {
		printer.Error(azerrors.ErrCliArguments)
		return aziclicommon.ErrCommandSilent
	}
	langFct, err := deps.GetLanguageFactory()
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	wksMgr, err := azicliwksmanager.NewInternalManager(ctx, langFct)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	aapPort := v.GetInt(azoptions.FlagName(commandNameForWorkspacesClone, flagAAP))
	papPort := v.GetInt(azoptions.FlagName(commandNameForWorkspacesClone, flagPAP))
	output, err := wksMgr.ExecCloneRepo(azplangcedar.LanguageIdentifier, repoURI, aapPort, papPort, outFunc(ctx, printer))
	if err != nil {
		azfiles.DeletePath(repoFolder)
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

// CreateCommandForWorkspaceClone creates a command for cloneializing a permguard workspace.
func CreateCommandForWorkspaceClone(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "clone",
		Short: "Clone a remote repository to the local permguard workspace",
		Long: aziclicommon.BuildCliLongTemplate(`This command clones a remote repository to the local permguard workspace.

Examples:
  # clone a remote repository to the local permguard workspace
  permguard clone 268786704340/magicfarmacia`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCloneWorkspace(args, deps, cmd, v)
		},
	}

	command.Flags().Int(flagAAP, 9091, "aap port")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspacesClone, flagAAP), command.Flags().Lookup(flagAAP))
	command.Flags().Int(flagPAP, 9092, "pap port")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspacesClone, flagPAP), command.Flags().Lookup(flagPAP))
	return command
}
