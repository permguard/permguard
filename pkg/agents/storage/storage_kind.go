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
	"slices"
	"strings"
)

const (
	// StorageNone represents no storage.
	StorageNone Kind = ""
	// StorageSQLite represents the SQLite storage kind.
	StorageSQLite Kind = "SQLITE"
)

// Kind is the type of storage.
type Kind string

// NewStorageKindFromString creates a new storage kind from a string.
func NewStorageKindFromString(storage string) (Kind, error) {
	return Kind(strings.ToUpper(storage)), nil
}

// String returns the string representation of the storage kind.
func (s Kind) String() string {
	return strings.ToUpper(string(s))
}

// Equal returns true if the storage kind is equal to the input storage kind.
func (s Kind) Equal(storage Kind) bool {
	return s.String() == storage.String()
}

// IsValid returns true if the storage kind is valid.
func (s Kind) IsValid(storages []Kind) bool {
	return slices.ContainsFunc(storages, s.Equal)
}
