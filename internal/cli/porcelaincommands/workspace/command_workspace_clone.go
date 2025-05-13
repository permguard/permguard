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
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/workspace"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
	"github.com/permguard/permguard/pkg/core/files"
)

const (
	// commandNameForWorkspacesClone is the command name for workspaces clone.
	commandNameForWorkspacesClone = "workspaces-clone"
)

// runECommandForCloneWorkspace runs the command for creating an workspace.
func runECommandForCloneWorkspace(args []string, deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	if len(args) < 1 {
		color.Red("Invalid arguments")
		return common.ErrCommandSilent
	}
	ledgerURI := strings.ToLower(args[0])
	if !strings.HasPrefix(ledgerURI, "permguard@") {
		color.Red("Invalid arguments")
		return common.ErrCommandSilent
	}
	ledger := strings.TrimPrefix(ledgerURI, "permguard@")
	elements := strings.Split(ledger, "/")
	if len(elements) < 3 {
		color.Red("Invalid arguments")
		return common.ErrCommandSilent
	}
	folder := elements[2]
	workDir, err := cmd.Flags().GetString(common.FlagWorkingDirectory)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	ledgerFolder := filepath.Join(workDir, folder)
	cmd.Flags().Set(common.FlagWorkingDirectory, ledgerFolder)
	if ok, _ := files.CheckPathIfExists(ledgerFolder); ok {
		color.Red(fmt.Sprintf("The ledger %s already exists", ledgerFolder))
		return common.ErrCommandSilent
	}
	files.CreateDirIfNotExists(ledgerFolder)

	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) < 1 {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to clone the workspace.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to clone the workspace")))
		}
		return common.ErrCommandSilent
	}
	langFct, err := deps.GetLanguageFactory()
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	wksMgr, err := workspace.NewInternalManager(ctx, langFct)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapPort := v.GetInt(options.FlagName(commandNameForWorkspacesClone, flagZAP))
	papPort := v.GetInt(options.FlagName(commandNameForWorkspacesClone, flagPAP))
	output, err := wksMgr.ExecCloneLedger(ledgerURI, zapPort, papPort, outFunc(ctx, printer))
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to clone the workspace.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(err, errors.New("cli: failed to clone the workspace")))
		}
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceClone creates a command for cloneializing a permguard workspace.
func CreateCommandForWorkspaceClone(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "clone",
		Short: "Clone a remote ledger to the local permguard workspace",
		Long: common.BuildCliLongTemplate(`This command clones a remote ledger to the local permguard workspace.

Examples:
  # clone a remote ledger to the local permguard workspace
  permguard clone localhost/273165098782/magicfarmacia`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCloneWorkspace(args, deps, cmd, v)
		},
	}

	command.Flags().Int(flagZAP, 9091, "specify the port number for the ZAP")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesClone, flagZAP), command.Flags().Lookup(flagZAP))
	command.Flags().Int(flagPAP, 9092, "specify the port number for the PAP")
	v.BindPFlag(options.FlagName(commandNameForWorkspacesClone, flagPAP), command.Flags().Lookup(flagPAP))
	return command
}
