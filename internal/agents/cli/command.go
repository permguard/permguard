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

	aziservers "github.com/permguard/permguard/internal/agents/servers"
	azservers "github.com/permguard/permguard/pkg/agents/servers"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

const (
	flagPrefixDataStorage          = "storage"
	flagSuffixDataStorageCentral   = "central.engine"
	flagValDefDataStorageCentral   = "sqlite"
	flagSuffixDataStorageProximity = "proximity.engine"
	flagValDefDataStorageProximity = "sqlite"
)

//go:embed "art.txt"
var asciiArt string

// addFlagsForCentralStorage adds the flags for the central storage.
func addFlagsForCentralStorage(flagSet *flag.FlagSet) error {
	flagSet.String(azoptions.FlagName(flagPrefixDataStorage, flagSuffixDataStorageCentral), flagValDefDataStorageCentral, "data storage type to be used for central data")
	return nil
}

// addFlagsForProximityStorage adds the flags for the proximity storage.
func addFlagsForProximityStorage(flagSet *flag.FlagSet) error {
	flagSet.String(azoptions.FlagName(flagPrefixDataStorage, flagSuffixDataStorageProximity), flagValDefDataStorageProximity, "data storage type to be used for proximity data")
	return nil
}

// addFlagsForServerInitalizer adds the flags for the server initializer.
func addFlagsForServerInitalizer(serverInitializer azservers.ServerInitializer, v *viper.Viper, command *cobra.Command, serverFactoryCfg *aziservers.ServerFactoryConfig, funcs []func(*flag.FlagSet) error) {
	var err error
	msgErroOnAddFlags := "Bootstrapper cannot add flags %s\n"

	if serverInitializer.HasCentralStorage() {
		err = azoptions.AddCobraFlags(command, v, addFlagsForCentralStorage)
		if err != nil {
			fmt.Printf(msgErroOnAddFlags, err.Error())
			os.Exit(1)
		}
	}
	if serverInitializer.HasProximityStorage() {
		err = azoptions.AddCobraFlags(command, v, addFlagsForProximityStorage)
		if err != nil {
			fmt.Printf(msgErroOnAddFlags, err.Error())
			os.Exit(1)
		}
	}

	err = azoptions.AddCobraFlags(command, v, serverFactoryCfg.AddFlags)
	if err != nil {
		fmt.Printf(msgErroOnAddFlags, err.Error())
		os.Exit(1)
	}

	if len(funcs) == 0 {
		err := azoptions.AddCobraFlags(command, v, funcs...)
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
func runECommand(cmdInfo *azservices.HostInfo, serverFactoryCfg *aziservers.ServerFactoryConfig, v *viper.Viper, startup func(*zap.Logger), shutdown func(*zap.Logger)) error {
	fmt.Println(asciiArt)
	fmt.Printf("PermGuard %s - Copyright © 2022 Nitro Agility S.r.l.\n", cmdInfo.Name)
	fmt.Println("")

	err := serverFactoryCfg.InitFromViper(v)
	if err != nil {
		fmt.Printf("Bootstrapper failed initializing server factory configuration %s\n", err)
		os.Exit(1)
	}
	serverFactory, err := aziservers.NewServerFactory(serverFactoryCfg)
	if err != nil {
		fmt.Printf("Bootstrapper failed  creating factory for  %s\n", cmdInfo.Name)
		os.Exit(1)
	}
	server, err := serverFactory.CreateServer()
	if err != nil {
		fmt.Printf("Bootstrapper failed  creating the server  %s\n", cmdInfo.Name)
		os.Exit(1)
	}

	logger := server.GetLogger()
	if startup != nil {
		startup(logger)
	}

	if server.HasDebug() {
		logger.Info("****************************************************")
		logger.Info("*** WARNING Application is running in debug mode ***")
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
func Run(serverInitializer azservers.ServerInitializer, startup func(*zap.Logger), shutdown func(*zap.Logger), funcs ...func(*flag.FlagSet) error) {
	if serverInitializer == nil {
		fmt.Printf("Bootstrapper cannot be initialized as the server initializer is nil\n")
		os.Exit(1)
	}

	v, err := azoptions.NewViper()
	if err != nil {
		fmt.Printf("Bootstrapper cannot create viper %s\n", err.Error())
		os.Exit(1)
	}

	centralStorageEngine := azstorage.StorageNone
	proximityStorageEngine := azstorage.StorageNone
	if serverInitializer.HasCentralStorage() {
		centralStorageEngine, err = azstorage.NewStorageKindFromString(stringFromArgs("--", azoptions.FlagName(flagPrefixDataStorage, flagSuffixDataStorageCentral), flagValDefDataStorageCentral, os.Args, v))
		if err != nil {
			fmt.Printf("Bootstrapper cannot parse the central storage engine %s\n", err.Error())
			os.Exit(1)
		}
	}
	if serverInitializer.HasProximityStorage() {
		proximityStorageEngine, err = azstorage.NewStorageKindFromString(stringFromArgs("--", azoptions.FlagName(flagPrefixDataStorage, flagSuffixDataStorageProximity), flagValDefDataStorageProximity, os.Args, v))
		if err != nil {
			fmt.Printf("Bootstrapper cannot parse the proximity storage engine %s\n", err.Error())
			os.Exit(1)
		}
	}

	serverFactoryCfg, err := aziservers.NewServerFactoryConfig(serverInitializer, centralStorageEngine, proximityStorageEngine)
	if err != nil {
		fmt.Printf("Bootstrapper cannot inizialize the server factory config %s\n", err.Error())
		os.Exit(1)
	}

	cmdInfo := serverInitializer.GetHostInfo()
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
