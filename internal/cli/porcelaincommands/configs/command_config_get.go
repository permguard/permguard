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
	ctx.AppendVerboseAction("reading zap endpoint from cli configuration")
	ctx.AppendVerboseFile(v.ConfigFileUsed())
	ctx.FlushVerboseDetails()
	zapEndpoint, err := ctx.ZAPEndpoint()
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to get the zap endpoint"), err))
		return common.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"zap_endpoint": zapEndpoint})
	return nil
}

// runECommandForPAPGet runs the command for getting the pap endpoint.
func runECommandForPAPGet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	ctx.AppendVerboseAction("reading pap endpoint from cli configuration")
	ctx.AppendVerboseFile(v.ConfigFileUsed())
	ctx.FlushVerboseDetails()
	papEndpoint, err := ctx.PAPEndpoint()
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to get the pap endpoint"), err))
		return common.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"pap_endpoint": papEndpoint})
	return nil
}

// runECommandForPDPGet runs the command for getting the pdp endpoint.
func runECommandForPDPGet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	ctx.AppendVerboseAction("reading pdp endpoint from cli configuration")
	ctx.AppendVerboseFile(v.ConfigFileUsed())
	ctx.FlushVerboseDetails()
	pdpEndpoint, err := ctx.PDPEndpoint()
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to get the pdp endpoint"), err))
		return common.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"pdp_endpoint": pdpEndpoint})
	return nil
}

// createCommandForConfigZAPGet creates the command for getting the zap endpoint.
func createCommandForConfigZAPGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "zap-endpoint",
		Short: "Get the zap endpoint",
		Long:  common.BuildCliLongTemplate(`This command gets the zap endpoint.`),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForZAPGet(deps, cmd, v)
		},
	}
	return command
}

// createCommandForConfigPAPGet creates the command for getting the pap endpoint.
func createCommandForConfigPAPGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pap-endpoint",
		Short: "Get the pap endpoint",
		Long:  common.BuildCliLongTemplate(`This command gets the pap endpoint.`),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForPAPGet(deps, cmd, v)
		},
	}
	return command
}

// createCommandForConfigPDPGet creates the command for getting the pdp endpoint.
func createCommandForConfigPDPGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pdp-endpoint",
		Short: "Get the pdp endpoint",
		Long:  common.BuildCliLongTemplate(`This command gets the pdp endpoint.`),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForPDPGet(deps, cmd, v)
		},
	}
	return command
}

// runECommandForAuthstarMaxObjectSizeGet runs the command for getting the authstar max object size.
func runECommandForAuthstarMaxObjectSizeGet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	ctx.AppendVerboseAction("reading authstar max object size from cli configuration")
	ctx.AppendVerboseFile(v.ConfigFileUsed())
	ctx.FlushVerboseDetails()
	maxObjectSize, err := ctx.AuthstarMaxObjectSize()
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to get the authstar max object size"), err))
		return common.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"authstar_max_object_size": maxObjectSize})
	return nil
}

// createCommandForConfigAuthstarMaxObjectSizeGet creates the command for getting the authstar max object size.
func createCommandForConfigAuthstarMaxObjectSizeGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "authstar-max-object-size",
		Short: "Get the authstar max object size",
		Long:  common.BuildCliLongTemplate(`This command gets the authstar max object size in bytes.`),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForAuthstarMaxObjectSizeGet(deps, cmd, v)
		},
	}
	return command
}

// runECommandForNOTPMaxPacketSizeGet runs the command for getting the notp max packet size.
func runECommandForNOTPMaxPacketSizeGet(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	ctx.AppendVerboseAction("reading notp max packet size from cli configuration")
	ctx.AppendVerboseFile(v.ConfigFileUsed())
	ctx.FlushVerboseDetails()
	maxPacketSize, err := ctx.NOTPMaxPacketSize()
	if err != nil {
		printer.Error(errors.Join(errors.New("cli: failed to get the notp max packet size"), err))
		return common.ErrCommandSilent
	}
	printer.PrintlnMap(map[string]any{"notp_max_packet_size": maxPacketSize})
	return nil
}

// createCommandForConfigNOTPMaxPacketSizeGet creates the command for getting the notp max packet size.
func createCommandForConfigNOTPMaxPacketSizeGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "notp-max-packet-size",
		Short: "Get the notp max packet size",
		Long:  common.BuildCliLongTemplate(`This command gets the notp max packet size in bytes.`),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForNOTPMaxPacketSizeGet(deps, cmd, v)
		},
	}
	return command
}

func createCommandForConfigGet(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "get",
		Short: "Get configuration items",
		Long:  common.BuildCliLongTemplate(`This command gets configuration items.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				color.Red(fmt.Sprintf("unknown config key %q; available keys: zap-endpoint, pap-endpoint, pdp-endpoint, authstar-max-object-size, notp-max-packet-size", args[0]))
				return common.ErrCommandSilent
			}
			return cmd.Help()
		},
	}
	command.AddCommand(createCommandForConfigZAPGet(deps, v))
	command.AddCommand(createCommandForConfigPAPGet(deps, v))
	command.AddCommand(createCommandForConfigPDPGet(deps, v))
	command.AddCommand(createCommandForConfigAuthstarMaxObjectSizeGet(deps, v))
	command.AddCommand(createCommandForConfigNOTPMaxPacketSizeGet(deps, v))
	return command
}
