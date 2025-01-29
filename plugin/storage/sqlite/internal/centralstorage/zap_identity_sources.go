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
	"fmt"

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelzap "github.com/permguard/permguard/pkg/transport/models/zap"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

const (
	IdentitySourceDefaultName = "default"
)

// CreateIdentitySource creates a new identity source.
func (s SQLiteCentralStorageZAP) CreateIdentitySource(identitySource *azmodelzap.IdentitySource) (*azmodelzap.IdentitySource, error) {
	if identitySource == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, "invalid client input - identity source is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInIdentitySource := &azirepos.IdentitySource{
		ZoneID: identitySource.ZoneID,
		Name:   identitySource.Name,
	}
	dbOutIdentitySource, err := s.sqlRepo.UpsertIdentitySource(tx, true, dbInIdentitySource)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentitySourceToAgentIdentitySource(dbOutIdentitySource)
}

// UpdateIdentitySource updates an identity source.
func (s SQLiteCentralStorageZAP) UpdateIdentitySource(identitySource *azmodelzap.IdentitySource) (*azmodelzap.IdentitySource, error) {
	if identitySource == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, "invalid client input - identity source is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInIdentitySource := &azirepos.IdentitySource{
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
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentitySourceToAgentIdentitySource(dbOutIdentitySource)
}

// DeleteIdentitySource deletes an identity source.
func (s SQLiteCentralStorageZAP) DeleteIdentitySource(zoneID int64, identitySourceID string) (*azmodelzap.IdentitySource, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutIdentitySource, err := s.sqlRepo.DeleteIdentitySource(tx, zoneID, identitySourceID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentitySourceToAgentIdentitySource(dbOutIdentitySource)
}

// FetchIdentitySources returns all identity sources.
func (s SQLiteCentralStorageZAP) FetchIdentitySources(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]azmodelzap.IdentitySource, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.GetDataFetchMaxPageSize() {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientPagination, fmt.Sprintf("invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *string
	if _, ok := fields[azmodelzap.FieldIdentitySourceIdentitySourceID]; ok {
		identitySourceID, ok := fields[azmodelzap.FieldIdentitySourceIdentitySourceID].(string)
		if !ok {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf("invalid client input - identity source id is not valid (identity source id: %s)", identitySourceID))
		}
		filterID = &identitySourceID
	}
	var filterName *string
	if _, ok := fields[azmodelzap.FieldIdentitySourceName]; ok {
		identitySourceName, ok := fields[azmodelzap.FieldIdentitySourceName].(string)
		if !ok {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf("invalid client input - identity source name is not valid (identity source name: %s)", identitySourceName))
		}
		filterName = &identitySourceName
	}
	dbIdentitySources, err := s.sqlRepo.FetchIdentitySources(db, page, pageSize, zoneID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	identitySources := make([]azmodelzap.IdentitySource, len(dbIdentitySources))
	for i, a := range dbIdentitySources {
		identitySource, err := mapIdentitySourceToAgentIdentitySource(&a)
		if err != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrStorageEntityMapping, fmt.Sprintf("failed to convert identity source entity (%s)", azirepos.LogIdentitySourceEntry(&a)), err)
		}
		identitySources[i] = *identitySource
	}
	return identitySources, nil
}
