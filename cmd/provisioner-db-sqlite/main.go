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

// Package main is the entry point for the SQLite database provisioner.
package main

import (
	"github.com/permguard/permguard/internal/provisioners/storage/cli"
	"github.com/permguard/permguard/pkg/provisioners/storage"
	"github.com/permguard/permguard/plugin/storage/sqlite"
)

// SQLiteStorageInitializer is the storage initializer.
type SQLiteStorageInitializer struct{}

// ProvisionerInfo returns the infos of the storage provisioner.
func (s *SQLiteStorageInitializer) ProvisionerInfo() storage.ProvisionerInfo {
	return storage.ProvisionerInfo{
		Name:  "SQLite Storage Provisioner",
		Use:   "Provision the SQLite storage",
		Short: "Provision the SQLite storage",
	}
}

// Provisioner returns the storage provisioner.
func (s *SQLiteStorageInitializer) Provisioner() (storage.Provisioner, error) {
	return sqlite.NewStorageProvisioner()
}

func main() {
	// Run the provisioner.
	cli.Run(&SQLiteStorageInitializer{})
}
