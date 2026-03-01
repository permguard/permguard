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
func runECommandForInitWorkspace(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
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

	name := v.GetString(options.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitName))
	authzLanguage := v.GetString(options.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitAuthzLanguage))
	authzTemplate := v.GetString(options.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitAuthzTemplate))
	zoneID := v.GetInt64(options.FlagName(commandNameForWorkspaceInit, common.FlagCommonZoneID))
	ledgerID := v.GetString(options.FlagName(commandNameForWorkspaceInit, common.FlagCommonLedgerID))
	initParams := &workspace.InitParms{
		Name:          name,
		AuthZLanguage: authzLanguage,
		AuthZTemplate: authzTemplate,
		ZoneID:        zoneID,
		LedgerID:      ledgerID,
	}
	output, err := wksMgr.ExecInitWorkspace(initParams, outFunc(ctx, printer))
	if err != nil {
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to initialize the workspace"), err))
		}
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForWorkspaceInit creates a command for initializing a permguard workspace.
func CreateCommandForWorkspaceInit(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "init",
		Short: "Initialize a permguard workspace",
		Long: common.BuildCliLongTemplate(`This command initializes a permguard workspace.

Examples:
  # initialize a new working directory
  permguard init
  # initialize a new working directory with a specific name
  permguard init myworkspace`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && !cmd.Flags().Changed(commandNameForWorkspacesInitName) {
				_ = cmd.Flags().Set(commandNameForWorkspacesInitName, args[0])
			}
			return runECommandForInitWorkspace(deps, cmd, v)
		},
	}

	command.Flags().String(commandNameForWorkspacesInitName, "", "specify the name of the workspace to initialize")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitName), command.Flags().Lookup(commandNameForWorkspacesInitName))

	command.Flags().String(commandNameForWorkspacesInitAuthzLanguage, "", "specify the authz language of the workspace to initialize")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitAuthzLanguage), command.Flags().Lookup(commandNameForWorkspacesInitAuthzLanguage))

	command.Flags().String(commandNameForWorkspacesInitAuthzTemplate, "", "specify the authz template of the workspace to initialize")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspaceInit, commandNameForWorkspacesInitAuthzTemplate), command.Flags().Lookup(commandNameForWorkspacesInitAuthzTemplate))

	command.Flags().Int64(common.FlagCommonZoneID, 0, "specify the zone id")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspaceInit, common.FlagCommonZoneID), command.Flags().Lookup(common.FlagCommonZoneID))

	command.Flags().String(common.FlagCommonLedgerID, "", "specify the ledger id")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspaceInit, common.FlagCommonLedgerID), command.Flags().Lookup(common.FlagCommonLedgerID))

	return command
}
