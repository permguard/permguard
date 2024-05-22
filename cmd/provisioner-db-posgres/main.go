/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	azcli "github.com/permguard/permguard/internal/provisioners/storage/cli"
	azstorage "github.com/permguard/permguard/pkg/provisioners/storage"
	azpostgres "github.com/permguard/permguard/plugin/storage/postgres"
)

// PosgresStorageInitializer is the storage initializer.
type PosgresStorageInitializer struct{}

// GetStorageProvisionerInfo returns the infos of the storage provisioner.
func (s *PosgresStorageInitializer) GetStorageProvisionerInfo() azstorage.StorageProvisionerInfo {
	return azstorage.StorageProvisionerInfo{
		Name:  "Postgres Storage Provisioner",
		Use:   "Provision the Postgres storage",
		Short: "Provision the Postgres storage",
	}
}

// GetStorageProvisioner returns the storage provisioner.
func (s *PosgresStorageInitializer) GetStorageProvisioner() (azstorage.StorageProvisioner, error) {
	return azpostgres.NewPostgresStorageProvisioner()
}

func main() {
	// Run the provisioner.
	azcli.Run(&PosgresStorageInitializer{})
}
