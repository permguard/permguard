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
	"github.com/permguard/permguard/pkg/agents/runtime"
)

// StorageConnector is the storage connector.
type StorageConnector struct {
	defaultStorageKind StorageKind
	factories          map[StorageKind]StorageFactoryProvider
}

// NewStorageConnector creates a new storage connector.
func NewStorageConnector(defaultStorageKind StorageKind, facatories map[StorageKind]StorageFactoryProvider) (*StorageConnector, error) {
	return &StorageConnector{
		defaultStorageKind: defaultStorageKind,
		factories:          facatories,
	}, nil
}

// CentralStorage returns the central storage.
func (s StorageConnector) CentralStorage(storageKind StorageKind, runtimeCotext runtime.RuntimeContext) (CentralStorage, error) {
	if storageKind == "" {
		storageKind = s.defaultStorageKind
	}
	storageCtx, err := NewStorageContext(runtimeCotext, storageKind)
	if err != nil {
		return nil, err
	}
	factory, err := s.factories[storageKind].CreateFactory()
	if err != nil {
		return nil, err
	}
	return factory.CreateCentralStorage(storageCtx)
}
