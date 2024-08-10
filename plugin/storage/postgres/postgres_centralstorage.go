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
	//azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// PostgresCentralStorage implements the postgres central storage.
type PostgresCentralStorage struct {
	ctx        *azstorage.StorageContext
	connection PostgresConnector
}

// newPostgresCentralStorage creates a new postgres central storage.
func newPostgresCentralStorage(storageContext *azstorage.StorageContext, connection PostgresConnector) (*PostgresCentralStorage, error) {
	return &PostgresCentralStorage{
		ctx:        storageContext,
		connection: connection,
	}, nil
}

// GetAAPCentralStorage returns the AAP central storage.
func (s PostgresCentralStorage) GetAAPCentralStorage() (azstorage.AAPCentralStorage, error) {
	return newPostgresAAPCentralStorage(s.ctx, s.connection)
}

// GetPAPCentralStorage returns the PAP central storage.
func (s PostgresCentralStorage) GetPAPCentralStorage() (azstorage.PAPCentralStorage, error) {
	return nil, nil //TODO: azerrors.WrapSystemError(azerrors.ErrNotImplemented, "storage: pap central storage has not been implemented by the postgres plugin.")
}
