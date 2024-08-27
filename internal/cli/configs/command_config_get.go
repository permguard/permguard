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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
)

// runECommandForAAPGet runs the command for getting the aap gRPC target.
func runECommandForAAPGet(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(aziclicommon.ErrorMessageCliBug)
		return aziclicommon.ErrCommandSilent
	}
	printer.Print(map[string]any{"aap_target": ctx.GetAAPTarget()})
	return nil
}

// runECommandForPAPGet runs the command for getting the pap gRPC target.
func runECommandForPAPGet(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(aziclicommon.ErrorMessageCliBug)
		return aziclicommon.ErrCommandSilent
	}
	printer.Print(map[string]any{"pap_target": ctx.GetPAPTarget()})
	return nil
}

// CreateCommandForConfig for managing config.
func createCommandForConfigAAPGet(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "aap-get-target",
		Short: "Get the app gRPC target",
		Long:  fmt.Sprintf(aziclicommon.CliLongTemplate, `This command gets the aap gRPC target.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForAAPGet(deps, cmd, v)
		},
	}
	return command
}

// CreateCommandForConfig for managing config.
func createCommandForConfigPAPGet(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pap-get-target",
		Short: "Get the pap gRPC target",
		Long:  fmt.Sprintf(aziclicommon.CliLongTemplate, `This command gets the pap gRPC target.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPAPGet(deps, cmd, v)
		},
	}
	return command
}
