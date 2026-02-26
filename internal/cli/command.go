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
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	commoncmds "github.com/permguard/permguard/internal/cli/commoncommands"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

// Build information variables.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// runECommand runs the command.
func runECommand(cmd *cobra.Command) error {
	return cmd.Help()
}

// Run the provisionier.
func Run(cliInitializer cli.Initializer) {
	// Create the command.
	v, err := options.NewViperFromConfig(func(_ *viper.Viper) map[string]any {
		mapValues := map[string]any{
			options.FlagName(common.FlagPrefixZAP, common.FlagSuffixZAPTarget): "localhost:9091",
			options.FlagName(common.FlagPrefixPAP, common.FlagSuffixPAPTarget): "localhost:9092",
			options.FlagName(common.FlagPrefixPDP, common.FlagSuffixPDPTarget): "localhost:9094",
		}
		return mapValues
	})
	if err != nil {
		os.Exit(1)
	}
	langFct, err := cliInitializer.LanguageFactory()
	if err != nil {
		os.Exit(1)
	}
	depsProvider, err := common.NewCliDependenciesProvider(langFct)
	if err != nil {
		os.Exit(1)
	}
	commands, err := cliInitializer.CliCommands(depsProvider, v)
	if err != nil {
		os.Exit(1)
	}
	cmdInfo := cliInitializer.Info()
	command := &cobra.Command{
		SilenceErrors: true,
		SilenceUsage:  true,
		Use:           cmdInfo.Use,
		Short:         cmdInfo.Short,
		Long:          cmdInfo.Long,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommand(cmd)
		},
	}

	command.PersistentFlags().StringP(common.FlagWorkingDirectory, common.FlagWorkingDirectoryShort, ".", "workdir")
	command.PersistentFlags().StringP(common.FlagOutput, common.FlagOutputShort, "terminal", "output format")
	command.PersistentFlags().BoolP(common.FlagVerbose, common.FlagVerboseShort, false, "true for verbose output")

	command.AddCommand(commoncmds.CreateCommandForVersion(depsProvider, v))

	// Add sub commands.
	for _, subCommand := range commands {
		command.AddCommand(subCommand)
	}

	// Execute the command.
	if err := command.Execute(); err != nil {
		if err != common.ErrCommandSilent {
			// TODO: fix error message
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
