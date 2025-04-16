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
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// commandNameForWorkspaceInit is the command name for workspace init.
	commandNameForWorkspaceInit = "workspace-init"
	// commandNameForWorkspacesInitName is name of the workspace to initialize.
	commandNameForWorkspacesInitName = "name"
	// commandNameForWorkspacesInitAuthzLanguage is the authz language of the workspace to initialize.
	commandNameForWorkspacesInitAuthzLanguage = "authz-language"
	// commandNameForWorkspacesInitAuthzTemplate is the authz template of the workspace to initialize.
	commandNameForWorkspacesInitAuthzTemplate = "authz-template"
)

// runECommandForInitWorkspace runs the command for creating an workspace.
func runECommandForInitWorkspace(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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

	name := v.GetString(azoptions.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitName))
	authzLanguage := v.GetString(azoptions.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitAuthzLanguage))
	authzTemplate := v.GetString(azoptions.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitAuthzTemplate))
	initParams := &azicliwksmanager.InitParms{
		Name:          name,
		AuthZLanguage: authzLanguage,
		AuthZTemplate: authzTemplate,
	}
	output, err := wksMgr.ExecInitWorkspace(initParams, outFunc(ctx, printer))
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to initialize the workspace.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliOperation, "failed to initialize the workspace.", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceInit creates a command for initializing a permguard workspace.
func CreateCommandForWorkspaceInit(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "init",
		Short: "Initialize a permguard workspace",
		Long: aziclicommon.BuildCliLongTemplate(`This command initializes a permguard workspace.

Examples:
  # initialize a new working directory
  permguard init`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForInitWorkspace(deps, cmd, v)
		},
	}

	command.Flags().String(commandNameForWorkspacesInitName, "", "specify the name of the workspace to initialize")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitName), command.Flags().Lookup(commandNameForWorkspacesInitName))

	command.Flags().String(commandNameForWorkspacesInitAuthzLanguage, "", "specify the authz language of the workspace to initialize")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitAuthzLanguage), command.Flags().Lookup(commandNameForWorkspacesInitAuthzLanguage))

	command.Flags().String(commandNameForWorkspacesInitAuthzTemplate, "", "specify the authz template of the workspace to initialize")
	v.BindPFlag(azoptions.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitAuthzTemplate), command.Flags().Lookup(commandNameForWorkspacesInitAuthzTemplate))

	return command
}
