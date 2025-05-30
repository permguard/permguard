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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
)

// runECommandForConfig runs the command for managing config.
func runECommandForConfig(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// CreateCommandForConfig for managing config.
func CreateCommandForConfig(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "config",
		Short: "Configure the command line settings",
		Long:  common.BuildCliLongTemplate(`This command configures the command line settings.`),
		RunE:  runECommandForConfig,
	}
	command.AddCommand(createCommandForConfigReset(deps, v))
	command.AddCommand(createCommandForConfigZAPGet(deps, v))
	command.AddCommand(createCommandForConfigZAPSet(deps, v))
	command.AddCommand(createCommandForConfigPAPGet(deps, v))
	command.AddCommand(createCommandForConfigPAPSet(deps, v))
	command.AddCommand(createCommandForConfigPDPGet(deps, v))
	command.AddCommand(createCommandForConfigPDPSet(deps, v))
	return command
}
