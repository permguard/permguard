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
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
)

// runECommandForZAPGet runs the command for getting the zap endpoint.
func runECommandForZAPGet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapTarget, err := ctx.ZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to get the zap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to get the zap target"), err))
		}
		return common.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"zap_target": zapTarget})
	return nil
}

// runECommandForPAPGet runs the command for getting the pap endpoint.
func runECommandForPAPGet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	papTarget, err := ctx.PAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to get the pap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to get the pap target"), err))
		}
		return common.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"pap_target": papTarget})
	return nil
}

// runECommandForPDPGet runs the command for getting the pdp endpoint.
func runECommandForPDPGet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	pdpTarget, err := ctx.PDPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to get the pdp target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to get the pdp target"), err))
		}
		return common.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"pdp_target": pdpTarget})
	return nil
}

// CreateCommandForConfig for managing config.
func createCommandForConfigZAPGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "zap-endpoint",
		Short: "Get the zap endpoint",
		Long:  common.BuildCliLongTemplate(`This command gets the zap grpc target.`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForZAPGet(deps, cmd, v)
		},
	}
	return command
}

// CreateCommandForConfig for managing config.
func createCommandForConfigPAPGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pap-endpoint",
		Short: "Get the pap endpoint",
		Long:  common.BuildCliLongTemplate(`This command gets the pap grpc target.`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForPAPGet(deps, cmd, v)
		},
	}
	return command
}

// CreateCommandForConfig for managing config.
func createCommandForConfigPDPGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pdp-endpoint",
		Short: "Get the pdp endpoint",
		Long:  common.BuildCliLongTemplate(`This command gets the pdp endpoint.`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForPDPGet(deps, cmd, v)
		},
	}
	return command
}

func createCommandForConfigGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "get",
		Short: "Get configuration items",
		Long:  common.BuildCliLongTemplate(`This command gets configuration items.`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	command.AddCommand(createCommandForConfigZAPGet(deps, v))
	command.AddCommand(createCommandForConfigPAPGet(deps, v))
	command.AddCommand(createCommandForConfigPDPGet(deps, v))
	return command
}
