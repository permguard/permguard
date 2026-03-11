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
func runECommandForCloneWorkspace(args []string, deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	// Parse and validate arguments before creating context.
	var validationErr error
	var ledgerURI, folder, ledgerFolder string
	if len(args) < 1 {
		validationErr = errors.New("cli: invalid arguments")
	} else {
		ledgerURI = strings.ToLower(args[0])
		if !strings.HasPrefix(ledgerURI, "permguard@") {
			validationErr = errors.New("cli: invalid arguments")
		} else {
			ledger := strings.TrimPrefix(ledgerURI, "permguard@")
			elements := strings.Split(ledger, "/")
			if len(elements) < 3 {
				validationErr = errors.New("cli: invalid arguments")
			} else {
				folder = elements[2]
			}
		}
	}

	// Set up working directory if validation passed.
	if validationErr == nil {
		workDir, err := cmd.Flags().GetString(common.FlagWorkingDirectory)
		if err != nil {
			validationErr = err
		} else {
			ledgerFolder = filepath.Join(workDir, folder)
			_ = cmd.Flags().Set(common.FlagWorkingDirectory, ledgerFolder)
		}
	}

	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	fail := func(err error) error {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to clone the workspace.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to clone the workspace"), err))
		}
		return common.ErrCommandSilent
	}

	if validationErr != nil {
		return fail(validationErr)
	}
	if ok, _ := files.CheckPathIfExists(ledgerFolder); ok {
		return fail(fmt.Errorf("cli: the ledger %s already exists", ledgerFolder))
	}
	if _, err := files.CreateDirIfNotExists(ledgerFolder); err != nil {
		return fail(err)
	}

	langFct, err := deps.LanguageFactory()
	if err != nil {
		return fail(err)
	}
	wksMgr, err := workspace.NewInternalManager(ctx, langFct)
	if err != nil {
		return fail(err)
	}
	zapPort := v.GetInt(options.FlagName(commandNameForWorkspacesClone, flagZAP))
	papPort := v.GetInt(options.FlagName(commandNameForWorkspacesClone, flagPAP))
	output, err := wksMgr.ExecCloneLedger(ledgerURI, zapPort, papPort, outFunc(ctx, printer))
	if err != nil {
		return fail(err)
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceClone creates a command for cloneializing a permguard workspace.
func CreateCommandForWorkspaceClone(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "clone",
		Short: "Clone a remote ledger to the local permguard workspace",
		Long: common.BuildCliLongTemplate(`This command clones a remote ledger to the local permguard workspace.

Examples:
  # clone a remote ledger to the local permguard workspace
  permguard clone localhost/273165098782/pharmaauthzflow`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCloneWorkspace(args, deps, cmd, v)
		},
	}

	command.Flags().Int(flagZAP, 9091, "specify the port number for the ZAP")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspacesClone, flagZAP), command.Flags().Lookup(flagZAP))
	command.Flags().Int(flagPAP, 9092, "specify the port number for the PAP")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspacesClone, flagPAP), command.Flags().Lookup(flagPAP))
	return command
}
