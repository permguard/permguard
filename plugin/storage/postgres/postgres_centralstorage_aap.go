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

package postgres

import (
	"fmt"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// PostgresCentralStorageAAP implements the postgres central storage.
type PostgresCentralStorageAAP struct {
	ctx        *azstorage.StorageContext
	connection PostgresConnector
}

// newPostgresAAPCentralStorage creates a new PostgresAAPCentralStorage.
func newPostgresAAPCentralStorage(storageContext *azstorage.StorageContext, connection PostgresConnector) (*PostgresCentralStorageAAP, error) {
	if storageContext == nil {
		return nil, fmt.Errorf("%q: %w", "storageContext is nil", azerrors.ErrInvalidInputParameter)
	}
	if connection == nil {
		return nil, fmt.Errorf("%q: %w", "connection is nil", azerrors.ErrInvalidInputParameter)
	}
	return &PostgresCentralStorageAAP{
		ctx:        storageContext,
		connection: connection,
	}, nil
}
