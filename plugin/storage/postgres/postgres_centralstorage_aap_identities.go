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
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// CreateIdentity creates a new identity.
func (s PostgresCentralStorageAAP) upsertIdentity(db *gorm.DB, isCreate bool, identity *azmodels.Identity) (*azmodels.Identity, error) {
	if identity == nil {
		return nil, fmt.Errorf("storage: %w", azerrors.ErrInvalidInputParameter)
	}
	if err := validateAccountID("identity", identity.AccountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", identity.AccountID, azerrors.ErrClientAccountID)
	}
	if err := validateName("identity", identity.Name); err != nil {
		return nil, fmt.Errorf("storage: invalid tenant name %q. %w", identity.Name, azerrors.ErrClientName)
	}
	kind, err := convertIdentityKindToID(identity.Kind)
	if err != nil {
		return nil, err
	}
	var dbIdentity Identity
	var result *gorm.DB
	if isCreate {
		var dbIdentitySource IdentitySource
		result = db.Where("account_id = ?", identity.AccountID).Where("identity_source_id = ?", identity.IdentitySourceID).First(&dbIdentitySource)
		if result.RowsAffected == 0 {
			return nil, fmt.Errorf("storage: identity source cannot be retrieved. %w", azerrors.ErrStorageNotFound)
		}
		dbIdentity = Identity{
			AccountID:        identity.AccountID,
			IdentitySourceID: dbIdentitySource.IdentitySourceID,
			Kind:             kind,
			Name:             identity.Name,
		}
		result = db.Omit("CreatedAt", "UpdatedAt").Create(&dbIdentity)
	} else {
		result = db.Where("account_id = ?", identity.AccountID).Where("identity_id = ?", identity.IdentityID).First(&dbIdentity)
		if result.RowsAffected == 0 {
			return nil, fmt.Errorf("storage: identity cannot be retrieved. %w", azerrors.ErrStorageNotFound)
		}
		dbIdentity.Kind = kind
		dbIdentity.Name = identity.Name
		result = db.Omit("CreatedAt", "UpdatedAt").Where("identity_id = ?", identity.IdentityID).Updates(&dbIdentity)
	}
	if result.RowsAffected == 0 || result.Error != nil {
		pgErr, ok := result.Error.(*pgconn.PgError)
		if ok && pgErr.Code == "23505" {
			return nil, fmt.Errorf("storage: identity cannot be created because of a duplicated name %w", azerrors.ErrStorageDuplicate)
		}
		return nil, fmt.Errorf("storage: identity cannot be created. %w", azerrors.ErrStorageGeneric)
	}
	return mapIdentityToAgentIdentity(&dbIdentity)
}

// CreateIdentity creates a new identity.
func (s PostgresCentralStorageAAP) CreateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertIdentity(db, true, identity)
}

// UpdateIdentity updates an identity.
func (s PostgresCentralStorageAAP) UpdateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertIdentity(db, false, identity)
}

// DeleteIdentity deletes an identity.
func (s PostgresCentralStorageAAP) DeleteIdentity(accountID int64, identityID string) (*azmodels.Identity, error) {
	if err := validateAccountID("identity", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}
	if err := validateUUID("identity", identityID); err != nil {
		return nil, fmt.Errorf("storage: invalid identity id %q. %w", IdentitySourceDefaultName, azerrors.ErrClientID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	var dbIdentity Identity
	result := db.Where("account_id = ?", accountID).Where("identity_id = ?", identityID).First(&dbIdentity)
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("storage: identity cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	result = db.Where("account_id = ?", accountID).Where("identity_id = ?", identityID).Delete(dbIdentity)
	if result.RowsAffected == 0 || result.Error != nil {
		return nil, fmt.Errorf("storage: identity cannot be deleted. %w", azerrors.ErrStorageGeneric)
	}
	return mapIdentityToAgentIdentity(&dbIdentity)
}

// GetAllIdentities returns all identities.
func (s PostgresCentralStorageAAP) GetAllIdentities(accountID int64, fields map[string]any) ([]azmodels.Identity, error) {
	if err := validateAccountID("identity", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	var identities []Identity
	query := db.Where("account_id = ?", accountID)
	if _, ok := fields[azmodels.FieldIdentityIdentityID]; ok {
		identityID, ok := fields[azmodels.FieldIdentityIdentityID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid tenant id. %w", azerrors.ErrClientUUID)
		}
		if err := validateUUID("identity", identityID); err != nil {
			return nil, fmt.Errorf("storage: invalid identity id %q. %w", identityID, azerrors.ErrClientUUID)
		}
		identityID = "%" + identityID + "%"
		query = query.Where("identity_id::text LIKE ?", identityID)
	}
	if _, ok := fields[azmodels.FieldIdentityIdentitySourceID]; ok {
		identitySourceID, ok := fields[azmodels.FieldIdentityIdentitySourceID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid identity source id. %w", azerrors.ErrClientUUID)
		}
		if err := validateUUID("identity", identitySourceID); err != nil {
			return nil, fmt.Errorf("storage: invalid identitysource id %q. %w", identitySourceID, azerrors.ErrClientUUID)
		}
		identitySourceID = "%" + identitySourceID + "%"
		query = query.Where("identity_source_id::text LIKE ?", identitySourceID)
	}
	if _, ok := fields[azmodels.FieldIdentityKind]; ok {
		kind, ok := fields[azmodels.FieldIdentityKind].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid identity kind. %w", azerrors.ErrClientGeneric)
		}
		cKind, err := convertIdentityKindToID(kind)
		if err != nil {
			return nil, err
		}
		query = query.Where("kind = ?", cKind)
	}
	if _, ok := fields[azmodels.FieldIdentityName]; ok {
		name, ok := fields[azmodels.FieldIdentityName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid tenant name. %w", azerrors.ErrClientName)
		}
		if err := validateName("identity", name); err != nil {
			return nil, fmt.Errorf("storage: invalid identitysource name %q. %w", name, azerrors.ErrClientName)
		}
		name = "%" + name + "%"
		query = query.Where("name LIKE ?", name)
	}
	result := query.Find(&identities)
	if result.Error != nil {
		return nil, fmt.Errorf("storage: identities cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	dbIdentities := make([]azmodels.Identity, len(identities))
	for i, a := range identities {
		identity, err := mapIdentityToAgentIdentity(&a)
		if err != nil {
			return nil, err
		}
		dbIdentities[i] = *identity
	}
	return dbIdentities, nil
}
