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
	"strings"
)

const (
	StorageNone     StorageKind = ""
	StorageBadger   StorageKind = "BADGER"
	StoragePostgres StorageKind = "POSTGRES"
)

// StorageKind is the type of storage.
type StorageKind string

// NewStorageKindFromString creates a new storage kind from a string.
func NewStorageKindFromString(storage string) (StorageKind, error) {
	return StorageKind(strings.ToUpper(storage)), nil
}

// String returns the string representation of the storage kind.
func (s StorageKind) String() string {
	return strings.ToUpper(string(s))
}

// Equal returns true if the storage kind is equal to the input storage kind.
func (s StorageKind) Equal(storage StorageKind) bool {
	return s.String() == storage.String()
}

// IsValid returns true if the storage kind is valid.
func (s StorageKind) IsValid(storages []StorageKind) bool {
	for _, svc := range storages {
		if s.Equal(svc) {
			return true
		}
	}
	return false
}
