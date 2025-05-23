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
	IdentityDefaultName = "default"
)

// CreateIdentity creates a new identity.
func (s SQLiteCentralStorageZAP) CreateIdentity(identity *zap.Identity) (*zap.Identity, error) {
	if identity == nil {
		return nil, errors.New("storage: invalid client input - identity is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	kind, err := repos.ConvertIdentityKindToID(identity.Kind)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("storage: invalid client input - identity kind %s is not valid", identity.Kind))
	}
	dbInIdentity := &repos.Identity{
		ZoneID:           identity.ZoneID,
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
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentityToAgentIdentity(dbOutIdentity)
}

// UpdateIdentity updates an identity.
func (s SQLiteCentralStorageZAP) UpdateIdentity(identity *zap.Identity) (*zap.Identity, error) {
	if identity == nil {
		return nil, errors.New("storage: invalid client input - identity is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	kind, err := repos.ConvertIdentityKindToID(identity.Kind)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("invalid client input - identity kind %s is not valid", identity.Kind))
	}
	dbInIdentity := &repos.Identity{
		IdentityID:       identity.IdentityID,
		ZoneID:           identity.ZoneID,
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
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentityToAgentIdentity(dbOutIdentity)
}

// DeleteIdentity deletes an identity.
func (s SQLiteCentralStorageZAP) DeleteIdentity(zoneID int64, identityID string) (*zap.Identity, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutIdentity, err := s.sqlRepo.DeleteIdentity(tx, zoneID, identityID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapIdentityToAgentIdentity(dbOutIdentity)
}

// FetchIdentities returns all identities.
func (s SQLiteCentralStorageZAP) FetchIdentities(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]zap.Identity, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.GetDataFetchMaxPageSize() {
		return nil, fmt.Errorf("invalid client input - page number %d or page size %d is not valid", page, pageSize)
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *string
	if _, ok := fields[zap.FieldIdentityIdentityID]; ok {
		identityID, ok := fields[zap.FieldIdentityIdentityID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - identity id is not valid (identity id: %s)", identityID)
		}
		filterID = &identityID
	}
	var filterName *string
	if _, ok := fields[zap.FieldIdentityName]; ok {
		identityName, ok := fields[zap.FieldIdentityName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - identity name is not valid (identity name: %s)", identityName)
		}
		filterName = &identityName
	}
	dbIdentities, err := s.sqlRepo.FetchIdentities(db, page, pageSize, zoneID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	identities := make([]zap.Identity, len(dbIdentities))
	for i, a := range dbIdentities {
		identity, err := mapIdentityToAgentIdentity(&a)
		if err != nil {
			return nil, errors.Join(err, fmt.Errorf("storage: failed to convert identity entity (%s)", repos.LogIdentityEntry(&a)))
		}
		identities[i] = *identity
	}
	return identities, nil
}
