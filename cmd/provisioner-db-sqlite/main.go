/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	azcli "github.com/permguard/permguard/internal/provisioners/storage/cli"
	azstorage "github.com/permguard/permguard/pkg/provisioners/storage"
	azsqlite "github.com/permguard/permguard/plugin/storage/sqlite"
)

// PosgresStorageInitializer is the storage initializer.
type PosgresStorageInitializer struct{}

// GetStorageProvisionerInfo returns the infos of the storage provisioner.
func (s *PosgresStorageInitializer) GetStorageProvisionerInfo() azstorage.StorageProvisionerInfo {
	return azstorage.StorageProvisionerInfo{
		Name:  "SQLite Storage Provisioner",
		Use:   "Provision the SQLite storage",
		Short: "Provision the SQLite storage",
	}
}

// GetStorageProvisioner returns the storage provisioner.
func (s *PosgresStorageInitializer) GetStorageProvisioner() (azstorage.StorageProvisioner, error) {
	return azsqlite.NewSQLiteStorageProvisioner()
}

func main() {
	// Run the provisioner.
	azcli.Run(&PosgresStorageInitializer{})
}
