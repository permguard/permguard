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

package centralstorage

import (
	"errors"
	"fmt"

	"github.com/permguard/permguard/pkg/transport/models/zap"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

const (
	IdentitySourceDefaultName = "default"
)

// CreateIdentitySource creates a new identity source.
func (s SQLiteCentralStorageZAP) CreateIdentitySource(identitySource *zap.IdentitySource) (*zap.IdentitySource, error) {
	if identitySource == nil {
		return nil, errors.New("storage: invalid client input - identity source is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInIdentitySource := &repos.IdentitySource{
		ZoneID: identitySource.ZoneID,
		Name:   identitySource.Name,
	}
	dbOutIdentitySource, err := s.sqlRepo.UpsertIdentitySource(tx, true, dbInIdentitySource)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentitySourceToAgentIdentitySource(dbOutIdentitySource)
}

// UpdateIdentitySource updates an identity source.
func (s SQLiteCentralStorageZAP) UpdateIdentitySource(identitySource *zap.IdentitySource) (*zap.IdentitySource, error) {
	if identitySource == nil {
		return nil, errors.New("storage: invalid client input - identity source is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInIdentitySource := &repos.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		ZoneID:           identitySource.ZoneID,
		Name:             identitySource.Name,
	}
	dbOutIdentitySource, err := s.sqlRepo.UpsertIdentitySource(tx, false, dbInIdentitySource)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentitySourceToAgentIdentitySource(dbOutIdentitySource)
}

// DeleteIdentitySource deletes an identity source.
func (s SQLiteCentralStorageZAP) DeleteIdentitySource(zoneID int64, identitySourceID string) (*zap.IdentitySource, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutIdentitySource, err := s.sqlRepo.DeleteIdentitySource(tx, zoneID, identitySourceID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentitySourceToAgentIdentitySource(dbOutIdentitySource)
}

// FetchIdentitySources returns all identity sources.
func (s SQLiteCentralStorageZAP) FetchIdentitySources(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]zap.IdentitySource, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.DataFetchMaxPageSize() {
		return nil, fmt.Errorf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize)
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *string
	if _, ok := fields[zap.FieldIdentitySourceIdentitySourceID]; ok {
		identitySourceID, ok := fields[zap.FieldIdentitySourceIdentitySourceID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - identity source id is not valid (identity source id: %s)", identitySourceID)
		}
		filterID = &identitySourceID
	}
	var filterName *string
	if _, ok := fields[zap.FieldIdentitySourceName]; ok {
		identitySourceName, ok := fields[zap.FieldIdentitySourceName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - identity source name is not valid (identity source name: %s)", identitySourceName)
		}
		filterName = &identitySourceName
	}
	dbIdentitySources, err := s.sqlRepo.FetchIdentitySources(db, page, pageSize, zoneID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	identitySources := make([]zap.IdentitySource, len(dbIdentitySources))
	for i, a := range dbIdentitySources {
		identitySource, err := mapIdentitySourceToAgentIdentitySource(&a)
		if err != nil {
			return nil, errors.Join(err, fmt.Errorf("storage: failed to convert identity source entity (%s)", repos.LogIdentitySourceEntry(&a)))
		}
		identitySources[i] = *identitySource
	}
	return identitySources, nil
}
