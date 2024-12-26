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
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// commandNameForWorkspacesCheckout is the command name for workspaces checkout.
	commandNameForWorkspacesCheckout = "workspaces.checkout"
)

// runECommandForCheckoutWorkspace runs the command for creating an workspace.
func runECommandForCheckoutWorkspace(args []string, deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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
	ledger := args[0]
	output, err := wksMgr.ExecCheckoutLedger(ledger, outFunc(ctx, printer))
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

// CreateCommandForWorkspaceCheckout creates a command for checkoutializing a permguard workspace.
func CreateCommandForWorkspaceCheckout(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "checkout",
		Short: `Check out the contents of a remote ledger to the local permguard workspace`,
		Long: aziclicommon.BuildCliLongTemplate(`This command checks out the contents of a remote ledger to the local permguard workspace.

Examples:
  # check out the contents of a remote ledger to the local permguard workspace
  permguard checkout origin/676095239339/ledgers/magicfarmacia`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCheckoutWorkspace(args, deps, cmd, v)
		},
	}
	return command
}
