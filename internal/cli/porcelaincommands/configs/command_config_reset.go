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

package configs

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
)

// runECommandReset runs the command for resetting the config.
func runECommandReset(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	configFile, err := options.ResetViperConfig(v)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to reset the cli config file.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliOperation, "failed to reset the cli config file.", err)
			printer.Error(sysErr)
		}
		return common.ErrCommandSilent
	}
	var output map[string]any
	if ctx.IsTerminalOutput() {
		printer.Println(fmt.Sprintf("The cli config file %s has been reset.", configFile))
	} else if ctx.IsJSONOutput() {
		output = map[string]any{
			"cli": map[string]any{
				"config_file": configFile,
			},
		}
		printer.PrintlnMap(output)
	}
	return nil
}

// CreateCommandForConfig for managing config.
func createCommandForConfigReset(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "reset",
		Short: "Reset the cli config settings",
		Long:  common.BuildCliLongTemplate(`This command resets the cli config settings.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandReset(deps, cmd, v)
		},
	}
	return command
}
