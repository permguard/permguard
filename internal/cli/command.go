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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azclicommons "github.com/permguard/permguard/internal/cli/commoncommands"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

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
func Run(cliInitializer azcli.CliInitializer) {
	// Create the command.
	v, err := azoptions.NewViperFromConfig(func(v *viper.Viper) map[string]any {
		mapValues := map[string]any{
			azoptions.FlagName(aziclicommon.FlagPrefixZAP, aziclicommon.FlagSuffixZAPTarget): "localhost:9091",
			azoptions.FlagName(aziclicommon.FlagPrefixPAP, aziclicommon.FlagSuffixPAPTarget): "localhost:9092",
			azoptions.FlagName(aziclicommon.FlagPrefixPDP, aziclicommon.FlagSuffixPDPTarget): "localhost:9094",
		}
		return mapValues
	})
	if err != nil {
		os.Exit(1)
	}
	langFct, err := cliInitializer.GetLanguageFactory()
	if err != nil {
		os.Exit(1)
	}
	depsProvider, err := aziclicommon.NewCliDependenciesProvider(langFct)
	if err != nil {
		os.Exit(1)
	}
	commands, err := cliInitializer.GetCliCommands(depsProvider, v)
	if err != nil {
		os.Exit(1)
	}
	cmdInfo := cliInitializer.GetCliInfo()
	command := &cobra.Command{
		SilenceErrors: true,
		SilenceUsage:  true,
		Use:           cmdInfo.Use,
		Short:         cmdInfo.Short,
		Long:          cmdInfo.Long,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommand(cmd)
		},
	}

	command.PersistentFlags().StringP(aziclicommon.FlagWorkingDirectory, aziclicommon.FlagWorkingDirectoryShort, ".", "workdir")
	command.PersistentFlags().StringP(aziclicommon.FlagOutput, aziclicommon.FlagOutputShort, "terminal", "output format")
	command.PersistentFlags().BoolP(aziclicommon.FlagVerbose, aziclicommon.FlagVerboseShort, false, "true for verbose output")

	command.AddCommand(azclicommons.CreateCommandForVersion(depsProvider, v))

	// Add sub commands.
	for _, subCommand := range commands {
		command.AddCommand(subCommand)
	}

	// Execute the command.
	if err := command.Execute(); err != nil {
		if err != aziclicommon.ErrCommandSilent {
			//TODO: fix error message
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
