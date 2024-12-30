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

package storage

import (
	azruntime "github.com/permguard/permguard/pkg/agents/runtime"
)

// StorageConnector is the storage connector.
type StorageConnector struct {
	factories            map[StorageKind]StorageFactoryProvider
	centralStorageEngine StorageKind
}

// NewStorageConnector creates a new storage connector.
func NewStorageConnector(centralStorageEngine StorageKind, facatories map[StorageKind]StorageFactoryProvider) (*StorageConnector, error) {
	return &StorageConnector{
		factories:            facatories,
		centralStorageEngine: centralStorageEngine,
	}, nil
}

// GetCentralStorage returns the central storage.
func (s StorageConnector) GetCentralStorage(runtimeCotext azruntime.RuntimeContext) (CentralStorage, error) {
	storageCtx, err := NewStorageContext(runtimeCotext, s.centralStorageEngine)
	if err != nil {
		return nil, err
	}
	factory, err := s.factories[s.centralStorageEngine].CreateFactory()
	if err != nil {
		return nil, err
	}
	return factory.CreateCentralStorage(storageCtx)
}
