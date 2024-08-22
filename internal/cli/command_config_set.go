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

package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azconfigs "github.com/permguard/permguard/pkg/configs"
	azvalidators "github.com/permguard/permguard/pkg/extensions/validators"
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

// runECommandForAAPSet runs the command for setting the aap gRPC target.
func runECommandForAAPSet(cmd *cobra.Command, v *viper.Viper, args []string) error {
	_, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red(errorMessageInvalidInputs)
		return ErrCommandSilent
	}
	if len(args) == 0 {
		printer.Error(fmt.Errorf(errorMessageInvalidInputs))
		return ErrCommandSilent
	}
	err = viperWriteEndpoint(v, azconfigs.FlagName(flagPrefixAAP, flagSuffixAAPTarget), args[0])
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
	}
	return nil
}

// runECommandForPAPSet runs the command for setting the pap gRPC target.
func runECommandForPAPSet(cmd *cobra.Command, v *viper.Viper, args []string) error {
	_, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red(errorMessageInvalidInputs)
		return ErrCommandSilent
	}
	if len(args) == 0 {
		printer.Error(fmt.Errorf(errorMessageInvalidInputs))
		return ErrCommandSilent
	}
	err = viperWriteEndpoint(v, azconfigs.FlagName(flagPrefixPAP, flagSuffixPAPTarget), args[0])
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
	}
	return nil
}

// createCommandForConfig for managing config.
func createCommandForConfigAAPSet(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "aap-set-target",
		Short: "Set the app gRPC target",
		Long: `This command sets the aap gRPC target.

Examples:
# set the aap gRPC target to localhost:9091
permguard config aap-set-target localhost:9091
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForAAPSet(cmd, v, args)
		},
	}
	return command
}

// createCommandForConfig for managing config.
func createCommandForConfigPAPSet(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "pap-set-target",
		Short: "Set the pap gRPC target",
		Long: `This command sets the pap gRPC target.

Examples:
# set the pap gRPC target to localhost:9092
permguard config pap-set-target localhost:9092
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForPAPSet(cmd, v, args)
		},
	}
	return command
}
