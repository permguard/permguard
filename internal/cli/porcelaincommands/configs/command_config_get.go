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
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// runECommandForZAPGet runs the command for getting the zap gRPC target.
func runECommandForZAPGet(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	zapTarget, err := ctx.GetZAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to get the zap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliOperation, "failed to get the zap target.", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"zap_target": zapTarget})
	return nil
}

// runECommandForPAPGet runs the command for getting the pap gRPC target.
func runECommandForPAPGet(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	papTarget, err := ctx.GetPAPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to get the pap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliOperation, "failed to get the pap target.", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"pap_target": papTarget})
	return nil
}

// runECommandForPDPGet runs the command for getting the pdp gRPC target.
func runECommandForPDPGet(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	pdpTarget, err := ctx.GetPDPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to get the pdp target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliOperation, "failed to get the pdp target.", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"pdp_target": pdpTarget})
	return nil
}

// CreateCommandForConfig for managing config.
func createCommandForConfigZAPGet(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "zap-get-target",
		Short: "Get the zap grpc target",
		Long:  aziclicommon.BuildCliLongTemplate(`This command gets the zap grpc target.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForZAPGet(deps, cmd, v)
		},
	}
	return command
}

// CreateCommandForConfig for managing config.
func createCommandForConfigPAPGet(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pap-get-target",
		Short: "Get the pap grpc target",
		Long:  aziclicommon.BuildCliLongTemplate(`This command gets the pap grpc target.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPAPGet(deps, cmd, v)
		},
	}
	return command
}

// CreateCommandForConfig for managing config.
func createCommandForConfigPDPGet(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pdp-get-target",
		Short: "Get the pdp grpc target",
		Long:  aziclicommon.BuildCliLongTemplate(`This command gets the pdp grpc target.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPDPGet(deps, cmd, v)
		},
	}
	return command
}
