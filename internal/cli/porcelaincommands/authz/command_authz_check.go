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

package authz

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForCheck is the command name for check.
	commandNameForCheck = "check"
)

// runECommandForCheck runs the command for executing check.
func runECommandForCheck(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	_, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	printer.PrintMap(map[string]any{})
	return nil
}
// createCommandForCheck creates a command for executing check.
func CreateCommandForCheck(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "check",
		Short: "Check an authorization request",
		Long: aziclicommon.BuildCliLongTemplate(`This command checks an authorization request.

Examples:
  # check an authorization request
  permguard authz check --appid 268786704340 --file /path/to/authorization_request.json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCheck(deps, cmd, v)
		},
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonApplicationID, 0, "application id")
	v.BindPFlag(azoptions.FlagName(commandNameForCheck, aziclicommon.FlagCommonApplicationID), command.PersistentFlags().Lookup(aziclicommon.FlagCommonApplicationID))

	command.PersistentFlags().StringP(aziclicommon.FlagCommonFile, aziclicommon.FlagCommonFileShort, "", "file containing the authorization request")
	v.BindPFlag(azoptions.FlagName(commandNameForCheck, aziclicommon.FlagCommonFile), command.PersistentFlags().Lookup(aziclicommon.FlagCommonFile))
	return command
}
