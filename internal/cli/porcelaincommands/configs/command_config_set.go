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
	"strconv"

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
	if !validators.IsValidEndpoint(value) {
		return errors.New("invalid endpoint: must be in the format scheme://hostname:port where scheme is grpc or grpcs")
	}
	valueMap := map[string]interface{}{
		key: value,
	}
	return options.OverrideViperFromConfig(v, valueMap)
}

// runECommandForZAPSet runs the command for setting the zap endpoint.
func runECommandForZAPSet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) == 0 {
		printer.Error(errors.Join(errors.New("cli: failed to set the zap endpoint"), err))
		return common.ErrCommandSilent
	}
	err = viperWriteEndpoint(v, options.FlagName(common.FlagPrefixZAP, common.FlagSuffixZAPEndpoint), args[0])
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to set the zap endpoint"), err))
		return common.ErrCommandSilent
	}
	if ctx.IsTerminalOutput() {
		printer.Println(fmt.Sprintf("zap_endpoint has been set to %s.", args[0]))
	}
	return nil
}

// runECommandForPAPSet runs the command for setting the pap endpoint.
func runECommandForPAPSet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) == 0 {
		printer.Error(errors.Join(errors.New("cli: failed to set the pap endpoint"), err))
		return common.ErrCommandSilent
	}
	err = viperWriteEndpoint(v, options.FlagName(common.FlagPrefixPAP, common.FlagSuffixPAPEndpoint), args[0])
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to set the pap endpoint"), err))
		return common.ErrCommandSilent
	}
	if ctx.IsTerminalOutput() {
		printer.Println(fmt.Sprintf("pap_endpoint has been set to %s.", args[0]))
	}
	return nil
}

// runECommandForPDPSet runs the command for setting the pdp endpoint.
func runECommandForPDPSet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) == 0 {
		printer.Error(errors.Join(errors.New("cli: failed to set the pdp endpoint"), err))
		return common.ErrCommandSilent
	}
	err = viperWriteEndpoint(v, options.FlagName(common.FlagPrefixPDP, common.FlagSuffixPDPEndpoint), args[0])
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to set the pdp endpoint"), err))
		return common.ErrCommandSilent
	}
	if ctx.IsTerminalOutput() {
		printer.Println(fmt.Sprintf("pdp_endpoint has been set to %s.", args[0]))
	}
	return nil
}

// createCommandForConfigZAPSet creates the command for setting the zap endpoint.
func createCommandForConfigZAPSet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "zap-endpoint",
		Short: "Set the zap endpoint",
		Long: common.BuildCliLongTemplate(`This command sets the zap endpoint.

Examples:
# set the zap endpoint to grpc://localhost:9091
permguard config set zap-endpoint grpc://localhost:9091
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForZAPSet(deps, cmd, v, args)
		},
	}
	return command
}

// createCommandForConfigPAPSet creates the command for setting the pap endpoint.
func createCommandForConfigPAPSet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pap-endpoint",
		Short: "Set the pap endpoint",
		Long: common.BuildCliLongTemplate(`This command sets the pap endpoint.

Examples:
# set the pap endpoint to grpc://localhost:9092
permguard config set pap-endpoint grpc://localhost:9092
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPAPSet(deps, cmd, v, args)
		},
	}
	return command
}

// createCommandForConfigPDPSet creates the command for setting the pdp endpoint.
func createCommandForConfigPDPSet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pdp-endpoint",
		Short: "Set the pdp endpoint",
		Long: common.BuildCliLongTemplate(`This command sets the pdp endpoint.

Examples:
# set the pdp endpoint to grpc://localhost:9094
permguard config set pdp-endpoint grpc://localhost:9094
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPDPSet(deps, cmd, v, args)
		},
	}
	return command
}

// runECommandForAuthstarMaxObjectSizeSet runs the command for setting the authstar max object size.
func runECommandForAuthstarMaxObjectSizeSet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) == 0 {
		printer.Error(errors.Join(errors.New("cli: failed to set the authstar max object size"), err))
		return common.ErrCommandSilent
	}
	size, err := strconv.Atoi(args[0])
	if err != nil || size <= 0 {
		printer.Error(errors.New("cli: authstar-max-object-size must be a positive integer"))
		return common.ErrCommandSilent
	}
	key := options.FlagName(common.FlagPrefixAuthstar, common.FlagSuffixAuthstarMaxObjectSize)
	valueMap := map[string]interface{}{
		key: size,
	}
	err = options.OverrideViperFromConfig(v, valueMap)
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to set the authstar max object size"), err))
		return common.ErrCommandSilent
	}
	if ctx.IsTerminalOutput() {
		printer.Println(fmt.Sprintf("authstar_max_object_size has been set to %d.", size))
	}
	return nil
}

// createCommandForConfigAuthstarMaxObjectSizeSet creates the command for setting the authstar max object size.
func createCommandForConfigAuthstarMaxObjectSizeSet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "authstar-max-object-size",
		Short: "Set the authstar max object size",
		Long: common.BuildCliLongTemplate(`This command sets the authstar max object size in bytes.

Examples:
# set the authstar max object size to 10MB
permguard config set authstar-max-object-size 10485760
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForAuthstarMaxObjectSizeSet(deps, cmd, v, args)
		},
	}
	return command
}

// runECommandForNOTPMaxPacketSizeSet runs the command for setting the notp max packet size.
func runECommandForNOTPMaxPacketSizeSet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if len(args) == 0 {
		printer.Error(errors.Join(errors.New("cli: failed to set the notp max packet size"), err))
		return common.ErrCommandSilent
	}
	size, err := strconv.Atoi(args[0])
	if err != nil || size <= 0 {
		printer.Error(errors.New("cli: notp-max-packet-size must be a positive integer"))
		return common.ErrCommandSilent
	}
	key := options.FlagName(common.FlagPrefixNOTP, common.FlagSuffixNOTPMaxPacketSize)
	valueMap := map[string]interface{}{
		key: size,
	}
	err = options.OverrideViperFromConfig(v, valueMap)
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to set the notp max packet size"), err))
		return common.ErrCommandSilent
	}
	if ctx.IsTerminalOutput() {
		printer.Println(fmt.Sprintf("notp_max_packet_size has been set to %d.", size))
	}
	return nil
}

// createCommandForConfigNOTPMaxPacketSizeSet creates the command for setting the notp max packet size.
func createCommandForConfigNOTPMaxPacketSizeSet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "notp-max-packet-size",
		Short: "Set the notp max packet size",
		Long: common.BuildCliLongTemplate(`This command sets the notp max packet size in bytes.

Examples:
# set the notp max packet size to 16MB
permguard config set notp-max-packet-size 16777216
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForNOTPMaxPacketSizeSet(deps, cmd, v, args)
		},
	}
	return command
}

func createCommandForConfigSet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "set",
		Short: "Set configuration items",
		Long:  common.BuildCliLongTemplate(`This command sets configuration items.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				color.Red(fmt.Sprintf("unknown config key %q; available keys: zap-endpoint, pap-endpoint, pdp-endpoint, authstar-max-object-size, notp-max-packet-size", args[0]))
			}
			return cmd.Help()
		},
	}
	command.AddCommand(createCommandForConfigZAPSet(deps, v))
	command.AddCommand(createCommandForConfigPAPSet(deps, v))
	command.AddCommand(createCommandForConfigPDPSet(deps, v))
	command.AddCommand(createCommandForConfigAuthstarMaxObjectSizeSet(deps, v))
	command.AddCommand(createCommandForConfigNOTPMaxPacketSizeSet(deps, v))
	return command
}
