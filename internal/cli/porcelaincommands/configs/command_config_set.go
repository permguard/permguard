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

	azvalidators "github.com/permguard/permguard-core/pkg/extensions/validators"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// viperWriteEndpoint writes the setting to the viper configuration.
func viperWriteEndpoint(v *viper.Viper, key string, value string) error {
	if !azvalidators.IsValidHostnamePort(value) {
		return fmt.Errorf("invalid hostname port")
	}
	err := v.ReadInConfig()
	if err != nil {
		return err
	}
	v.Set(key, value)
	return v.WriteConfig()
}

// runECommandForZAPSet runs the command for setting the zap gRPC target.
func runECommandForZAPSet(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	if len(args) == 0 {
		printer.Error(azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "invalid input"))
		return aziclicommon.ErrCommandSilent
	}
	err = viperWriteEndpoint(v, azoptions.FlagName(aziclicommon.FlagPrefixZAP, aziclicommon.FlagSuffixZAPTarget), args[0])
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed to set the zone value.")
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	return nil
}

// runECommandForPAPSet runs the command for setting the pap gRPC target.
func runECommandForPAPSet(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	if len(args) == 0 {
		printer.Error(azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "invalid input"))
		return aziclicommon.ErrCommandSilent
	}
	err = viperWriteEndpoint(v, azoptions.FlagName(aziclicommon.FlagPrefixPAP, aziclicommon.FlagSuffixPAPTarget), args[0])
	if err != nil {
		if ctx.IsTerminalOutput() {
			printer.Println("Failed to set the pap value.")
			if ctx.IsVerboseTerminalOutput() {
				printer.Error(err)
			}
		}
		return aziclicommon.ErrCommandSilent
	}
	return nil
}

// CreateCommandForConfig for managing config.
func createCommandForConfigZAPSet(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "zap-set-target",
		Short: "Set the zone grpc target",
		Long: aziclicommon.BuildCliLongTemplate(`This command sets the zap grpc target.

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
func createCommandForConfigPAPSet(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pap-set-target",
		Short: "Set the pap grpc target",
		Long: aziclicommon.BuildCliLongTemplate(`This command sets the pap grpc target.

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
