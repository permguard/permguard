package cli

import (
	"fmt"
	"os"

	_ "embed"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/pkg/cli/options"
	"github.com/permguard/permguard/pkg/provisioners/storage"
)

//go:embed "art.txt"
var asciiArt string

// runECommand runs the command.
func runECommand(cmdInfo storage.StorageProvisionerInfo, storageProvisioner storage.StorageProvisioner, v *viper.Viper) error {
	fmt.Println(asciiArt)
	fmt.Printf("Permguard %s - Copyright © 2022 Nitro Agility S.r.l.\n", cmdInfo.Name)
	fmt.Println("")

	err := storageProvisioner.InitFromViper(v)
	if err != nil {
		return err
	}

	err = storageProvisioner.Down()
	if err != nil {
		return err
	}
	err = storageProvisioner.Up()
	if err != nil {
		return err
	}
	return nil
}

// Run the provisionier.
func Run(provisionerInitializer storage.StorageProvisionerInitializer) {
	if provisionerInitializer == nil {
		fmt.Printf("Storage provisioner cannot be nil\n")
		os.Exit(1)
	}

	// Create the command.
	v, err := options.NewViper()
	if err != nil {
		fmt.Printf("Storage provisioner cannot create viper %s\n", err.Error())
		os.Exit(1)
	}

	storageProvisioner, err := provisionerInitializer.GetStorageProvisioner()
	if err != nil {
		fmt.Printf("Storage provisioner cannot add flags %s\n", err.Error())
		os.Exit(1)
	}

	cmdInfo := provisionerInitializer.GetStorageProvisionerInfo()
	command := &cobra.Command{
		Use:   cmdInfo.Use,
		Short: cmdInfo.Short,
		Long:  cmdInfo.Long,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommand(cmdInfo, storageProvisioner, v)
		},
	}

	err = options.AddCobraFlags(command, v, storageProvisioner.AddFlags)
	if err != nil {
		fmt.Printf("Storage provisioner cannot add flags %s\n", err.Error())
		os.Exit(1)
	}

	// Execute the command.
	if err := command.Execute(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
