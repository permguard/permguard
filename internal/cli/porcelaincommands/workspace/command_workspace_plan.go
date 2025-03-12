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
	// commandNameForWorkspacesPlan is the command name for workspaces plan.
	commandNameForWorkspacesPlan = "workspaces-plan"
)

// runECommandForPlanWorkspace runs the command for creating an workspace.
func runECommandForPlanWorkspace(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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
	output, err := wksMgr.ExecPlan(outFunc(ctx, printer))
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed execute the plan.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliOperation, "failed to execute the plan.", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspacePlan creates a command for planializing a permguard workspace.
func CreateCommandForWorkspacePlan(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "plan",
		Short: "Generate a plan of changes to apply to the remote ledger based on the differences between the local and remote states",
		Long: aziclicommon.BuildCliLongTemplate(`This command generates a plan of changes to apply to the remote ledger based on the differences between the local and remote states.

Examples:
  # generate a plan of changes to apply to the remote ledger based on the differences between the local and remote states
  permguard plan`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPlanWorkspace(deps, cmd, v)
		},
	}
	return command
}
