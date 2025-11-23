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

	"github.com/permguard/permguard/common/pkg/extensions/validators"
	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

// viperWriteEndpoint writes the setting to the viper configuration.
func viperWriteEndpoint(v *viper.Viper, key string, value string) error {
	if !validators.IsValidHostnamePort(value) {
		return fmt.Errorf("invalid hostname:port")
	}
	valueMap := map[string]interface{}{
		key: value,
	}
	return options.OverrideViperFromConfig(v, valueMap)
}

// runECommandForZAPSet runs the command for setting the zap gRPC target.
func runECommandForZAPSet(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) == 0 {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to set the zap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to set the zap target"), err))
		}
		return common.ErrCommandSilent
	}
	err = viperWriteEndpoint(v, options.FlagName(common.FlagPrefixZAP, common.FlagSuffixZAPTarget), args[0])
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to set the zap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to set the zap target"), err))
		}
		return common.ErrCommandSilent
	}
	return nil
}

// runECommandForPAPSet runs the command for setting the pap gRPC target.
func runECommandForPAPSet(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) == 0 {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to set the pap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to set the pap target"), err))
		}
		return common.ErrCommandSilent
	}
	err = viperWriteEndpoint(v, options.FlagName(common.FlagPrefixPAP, common.FlagSuffixPAPTarget), args[0])
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to set the pap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to set the pap target"), err))
		}
		return common.ErrCommandSilent
	}
	return nil
}

// runECommandForPDPSet runs the command for setting the pdp gRPC target.
func runECommandForPDPSet(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) == 0 {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to set the zap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to set the pdp target"), err))
		}
		return common.ErrCommandSilent
	}
	err = viperWriteEndpoint(v, options.FlagName(common.FlagPrefixPDP, common.FlagSuffixPDPTarget), args[0])
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to set the zap target.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: failed to set the pdp target"), err))
		}
		return common.ErrCommandSilent
	}
	return nil
}

// CreateCommandForConfig for managing config.
func createCommandForConfigZAPSet(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "zap-set-target",
		Short: "Set the zap grpc target",
		Long: common.BuildCliLongTemplate(`This command sets the zap grpc target.

Examples:
# set the zap gRPC target to localhost:9091
permguard config zap-set-target localhost:9091
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForZAPSet(deps, cmd, v, args)
		},
	}
	return command
}

// CreateCommandForConfig for managing config.
func createCommandForConfigPAPSet(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pap-set-target",
		Short: "Set the pap grpc target",
		Long: common.BuildCliLongTemplate(`This command sets the pap grpc target.

Examples:
# set the pap gRPC target to localhost:9092
permguard config pap-set-target localhost:9092
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPAPSet(deps, cmd, v, args)
		},
	}
	return command
}

// CreateCommandForConfig for managing config.
func createCommandForConfigPDPSet(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pdp-set-target",
		Short: "Set the pdp grpc target",
		Long: common.BuildCliLongTemplate(`This command sets the pdp grpc target.

Examples:
# set the pdp gRPC target to localhost:9094
permguard config pdp-set-target localhost:9094
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPDPSet(deps, cmd, v, args)
		},
	}
	return command
}
