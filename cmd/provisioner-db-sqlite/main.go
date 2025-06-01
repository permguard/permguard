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

package main

import (
	"github.com/permguard/permguard/internal/provisioners/storage/cli"
	"github.com/permguard/permguard/pkg/provisioners/storage"
	"github.com/permguard/permguard/plugin/storage/sqlite"
)

// PosgresStorageInitializer is the storage initializer.
type PosgresStorageInitializer struct{}

// StorageProvisionerInfo returns the infos of the storage provisioner.
func (s *PosgresStorageInitializer) StorageProvisionerInfo() storage.StorageProvisionerInfo {
	return storage.StorageProvisionerInfo{
		Name:  "SQLite Storage Provisioner",
		Use:   "Provision the SQLite storage",
		Short: "Provision the SQLite storage",
	}
}

// StorageProvisioner returns the storage provisioner.
func (s *PosgresStorageInitializer) StorageProvisioner() (storage.StorageProvisioner, error) {
	return sqlite.NewSQLiteStorageProvisioner()
}

func main() {
	// Run the provisioner.
	cli.Run(&PosgresStorageInitializer{})
}
