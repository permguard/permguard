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
	azmodelaap "github.com/permguard/permguard/pkg/transport/models/aap"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

const (
	IdentityDefaultName = "default"
)

// CreateIdentity creates a new identity.
func (s SQLiteCentralStorageAAP) CreateIdentity(identity *azmodelaap.Identity) (*azmodelaap.Identity, error) {
	if identity == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - identity is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	kind, err := azirepos.ConvertIdentityKindToID(identity.Kind)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity kind %s is not valid", identity.Kind))
	}
	dbInIdentity := &azirepos.Identity{
		ApplicationID:    identity.ApplicationID,
		IdentitySourceID: identity.IdentitySourceID,
		Kind:             kind,
		Name:             identity.Name,
	}
	dbOutIdentity, err := s.sqlRepo.UpsertIdentity(tx, true, dbInIdentity)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentityToAgentIdentity(dbOutIdentity)
}

// UpdateIdentity updates an identity.
func (s SQLiteCentralStorageAAP) UpdateIdentity(identity *azmodelaap.Identity) (*azmodelaap.Identity, error) {
	if identity == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - identity is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	kind, err := azirepos.ConvertIdentityKindToID(identity.Kind)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity kind %s is not valid", identity.Kind))
	}
	dbInIdentity := &azirepos.Identity{
		IdentityID:       identity.IdentityID,
		ApplicationID:    identity.ApplicationID,
		IdentitySourceID: identity.IdentitySourceID,
		Kind:             kind,
		Name:             identity.Name,
	}
	dbOutIdentity, err := s.sqlRepo.UpsertIdentity(tx, false, dbInIdentity)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentityToAgentIdentity(dbOutIdentity)
}

// DeleteIdentity deletes an identity.
func (s SQLiteCentralStorageAAP) DeleteIdentity(applicationID int64, identityID string) (*azmodelaap.Identity, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutIdentity, err := s.sqlRepo.DeleteIdentity(tx, applicationID, identityID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentityToAgentIdentity(dbOutIdentity)
}

// FetchIdentities returns all identities.
func (s SQLiteCentralStorageAAP) FetchIdentities(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodelaap.Identity, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.GetDataFetchMaxPageSize() {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *string
	if _, ok := fields[azmodelaap.FieldIdentityIdentityID]; ok {
		identityID, ok := fields[azmodelaap.FieldIdentityIdentityID].(string)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity id is not valid (identity id: %s)", identityID))
		}
		filterID = &identityID
	}
	var filterName *string
	if _, ok := fields[azmodelaap.FieldIdentityName]; ok {
		identityName, ok := fields[azmodelaap.FieldIdentityName].(string)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity name is not valid (identity name: %s)", identityName))
		}
		filterName = &identityName
	}
	dbIdentities, err := s.sqlRepo.FetchIdentities(db, page, pageSize, applicationID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	identities := make([]azmodelaap.Identity, len(dbIdentities))
	for i, a := range dbIdentities {
		identity, err := mapIdentityToAgentIdentity(&a)
		if err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrStorageEntityMapping, fmt.Sprintf("storage: failed to convert identity entity (%s)", azirepos.LogIdentityEntry(&a)))
		}
		identities[i] = *identity
	}
	return identities, nil
}
