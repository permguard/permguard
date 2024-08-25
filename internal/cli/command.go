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
	"errors"
	"fmt"
	"os"

	_ "embed"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	flagOutput              = "output"
	flagOutputShort         = "o"
	flagVerbose             = "verbose"
	flagVerboseShort        = "v"
	flagCommonPage          = "page"
	flagCommonPageShort     = "p"
	flagCommonPageSize      = "size"
	flagCommonPageSizeShort = "s"
	flagCommonAccountID     = "account"
	flagCommonName          = "name"
	flagCommonEmail         = "email"
	flagCommonDescription   = "description"
	flagCommonFile          = "file"
	flagCommonFileShort     = "f"
	flagPrefixAAP           = "aap"
	flagSuffixAAPTarget     = "target"
	flagPrefixPAP           = "pap"
	flagSuffixPAPTarget     = "target"
)

//go:embed "art.txt"
var asciiArt string

var cliLongTemplate = `The official PermGuard CLI
Copyright © 2022 Nitro Agility S.r.l.

%s

  Find more information at: https://www.permguard.com/docs/cli/how-to-use/`

var ErrCommandSilent = errors.New("command: silent error")

// runECommand runs the command.
func runECommand(cmdInfo azcli.CliInfo, cmd *cobra.Command) error {
	fmt.Println(asciiArt)
	fmt.Printf("PermGuard %s - Copyright © 2022 Nitro Agility S.r.l.\n", cmdInfo.Name)
	fmt.Println("")
	return cmd.Help()
}

// Run the provisionier.
func Run(commandsInitializer azcli.CliInitializer) {
	// Create the command.
	v, err := azconfigs.NewViperFromConfig(func(v *viper.Viper) error {
		v.SetDefault(azconfigs.FlagName(flagPrefixAAP, flagSuffixAAPTarget), "localhost:9091")
		v.SetDefault(azconfigs.FlagName(flagPrefixPAP, flagSuffixPAPTarget), "localhost:9092")
		return v.WriteConfig()
	})
	if err != nil {
		os.Exit(1)
	}

	depsProvider, err := NewCLIDependenciesProvider()
	if err != nil {
		os.Exit(1)
	}
	commands, err := commandsInitializer.GetCliCommands(depsProvider, v)
	if err != nil {
		os.Exit(1)
	}

	cmdInfo := commandsInitializer.GetCliInfo()
	command := &cobra.Command{
		SilenceErrors: true,
		SilenceUsage:  true,
		Use:           cmdInfo.Use,
		Short:         cmdInfo.Short,
		Long:          cmdInfo.Long,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommand(cmdInfo, cmd)
		},
	}

	command.PersistentFlags().StringP(flagOutput, flagOutputShort, "terminal", "output format")
	command.PersistentFlags().BoolP(flagVerbose, flagVerboseShort, false, "true for verbose output")

	// Add sub commands.
	for _, subCommand := range commands {
		command.AddCommand(subCommand)
	}

	// Execute the command.
	if err := command.Execute(); err != nil {
		if err != ErrCommandSilent {
			// TODO: fix error message
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
