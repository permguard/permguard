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
	"context"
	"flag"
	"fmt"
	"os"

	_ "embed"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	iservers "github.com/permguard/permguard/internal/agents/servers"
	"github.com/permguard/permguard/pkg/agents/servers"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	flagPrefixDataStorage        = "storage"
	flagSuffixDataStorageCentral = "engine-central"
	flagValDefDataStorageCentral = "SQLITE"
)

//go:embed "art.txt"
var asciiArt string

var (
	Version   string
	BuildTime string
	GitCommit string
)

// addFlagsForCentralStorage adds the flags for the central storage.
func addFlagsForCentralStorage(flagSet *flag.FlagSet) error {
	flagSet.String(options.FlagName(flagPrefixDataStorage, flagSuffixDataStorageCentral), flagValDefDataStorageCentral, "data storage type to be used for central data")
	return nil
}

// addFlagsForServerInitalizer adds the flags for the server initializer.
func addFlagsForServerInitalizer(serverInitializer servers.ServerInitializer, v *viper.Viper, command *cobra.Command, serverFactoryCfg *iservers.ServerFactoryConfig, funcs []func(*flag.FlagSet) error) {
	var err error
	msgErroOnAddFlags := "Bootstrapper cannot add flags %s\n"

	if serverInitializer.HasCentralStorage() {
		err = options.AddCobraFlags(command, v, addFlagsForCentralStorage)
		if err != nil {
			fmt.Printf(msgErroOnAddFlags, err.Error())
			os.Exit(1)
		}
	}

	err = options.AddCobraFlags(command, v, serverFactoryCfg.AddFlags)
	if err != nil {
		fmt.Printf(msgErroOnAddFlags, err.Error())
		os.Exit(1)
	}

	if len(funcs) == 0 {
		err := options.AddCobraFlags(command, v, funcs...)
		if err != nil {
			fmt.Printf(msgErroOnAddFlags, err.Error())
			os.Exit(1)
		}
	}

	if err := command.Execute(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

// runECommand runs the command.
func runECommand(cmdInfo *services.HostInfo, serverFactoryCfg *iservers.ServerFactoryConfig, v *viper.Viper, startup func(*zap.Logger), shutdown func(*zap.Logger)) error {
	if Version == "" {
		Version = "none"
	}
	if BuildTime == "" {
		BuildTime = "unknown"
	}
	if GitCommit == "" {
		GitCommit = "unknown"
	}

	fmt.Println(asciiArt)
	fmt.Printf("Permguard %s v.%s - Copyright © 2022 Nitro Agility S.r.l. \n", cmdInfo.Name, Version)
	fmt.Println("")

	err := serverFactoryCfg.InitFromViper(v)
	if err != nil {
		fmt.Printf("Bootstrapper failed initializing server factory configuration %s\n", err)
		os.Exit(1)
	}
	serverFactory, err := iservers.NewServerFactory(serverFactoryCfg)
	if err != nil {
		fmt.Printf("Bootstrapper failed  creating factory for  %s\n", cmdInfo.Name)
		os.Exit(1)
	}
	server, err := serverFactory.CreateServer()
	if err != nil {
		fmt.Printf("Bootstrapper failed  creating the server  %s\n", cmdInfo.Name)
		os.Exit(1)
	}

	logger := server.Logger()
	if startup != nil {
		startup(logger)
	}

	logger.Info(fmt.Sprintf("version %s", Version), zap.String("version", Version), zap.String("buildTime", BuildTime), zap.String("gitCommit", GitCommit))

	if server.HasDebug() {
		logger.Info("****************************************************")
		logger.Info("*** WARNING Zone is running in debug mode ***")
		logger.Info("****************************************************")
	}

	exited, err := server.Serve(context.Background(), func() {
		if shutdown != nil {
			shutdown(logger)
		}
	})
	if exited {
		return nil
	}
	return err
}

// Run starts the server and runs the startup and shutdown functions.
func Run(serverInitializer servers.ServerInitializer, startup func(*zap.Logger), shutdown func(*zap.Logger), funcs ...func(*flag.FlagSet) error) {
	if serverInitializer == nil {
		fmt.Printf("Bootstrapper cannot be initialized as the server initializer is nil\n")
		os.Exit(1)
	}

	v, err := options.NewViper()
	if err != nil {
		fmt.Printf("Bootstrapper cannot create viper %s\n", err.Error())
		os.Exit(1)
	}

	centralStorageEngine := storage.StorageNone
	if serverInitializer.HasCentralStorage() {
		centralStorageEngine, err = storage.NewStorageKindFromString(stringFromArgs("--", options.FlagName(flagPrefixDataStorage, flagSuffixDataStorageCentral), flagValDefDataStorageCentral, os.Args, v))
		if err != nil {
			fmt.Printf("Bootstrapper cannot parse the central storage engine %s\n", err.Error())
			os.Exit(1)
		}
	}

	serverFactoryCfg, err := iservers.NewServerFactoryConfig(serverInitializer, centralStorageEngine)
	if err != nil {
		fmt.Printf("Bootstrapper cannot inizialize the server factory config %s\n", err.Error())
		os.Exit(1)
	}

	cmdInfo := serverInitializer.HostInfo()

	command := &cobra.Command{
		Use:   cmdInfo.Use,
		Short: cmdInfo.Short,
		Long:  cmdInfo.Long,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommand(cmdInfo, serverFactoryCfg, v, startup, shutdown)
		},
	}

	// Add flags.
	// Execute the command.
	addFlagsForServerInitalizer(serverInitializer, v, command, serverFactoryCfg, funcs)
}
