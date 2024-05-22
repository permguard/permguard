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

const (
	IdentitySourceDefaultName = "default"
)

// CreateIdentitySource creates a new identity source.
func (s PostgresCentralStorageAAP) upsertIdentitySource(db *gorm.DB, isCreate bool, identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error) {
	if identitySource == nil {
		return nil, fmt.Errorf("storage: %w", azerrors.ErrInvalidInputParameter)
	}
	if err := validateAccountID("identitysource", identitySource.AccountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", identitySource.AccountID, azerrors.ErrClientAccountID)
	}
	if err := validateName("identitysource", identitySource.Name); err != nil {
		return nil, fmt.Errorf("storage: invalid identity source name %q. %w", identitySource.Name, azerrors.ErrClientName)
	}
	if !isCreate && identitySource.Name == IdentitySourceDefaultName {
		return nil, fmt.Errorf("storage: identity source cannot be updated with a default name. %w", azerrors.ErrClientName)
	}

	var dbIdentitySource IdentitySource
	var result *gorm.DB
	if isCreate {
		dbIdentitySource = IdentitySource{
			AccountID: identitySource.AccountID,
			Name:      identitySource.Name,
		}
		result = db.Omit("CreatedAt", "UpdatedAt").Create(&dbIdentitySource)
	} else {
		result = db.Where("account_id = ?", identitySource.AccountID).Where("identity_source_id = ?", identitySource.IdentitySourceID).First(&dbIdentitySource)
		if result.RowsAffected == 0 {
			return nil, fmt.Errorf("storage: identity source cannot be retrieved. %w", azerrors.ErrStorageNotFound)
		}
		dbIdentitySource.Name = identitySource.Name
		result = db.Omit("CreatedAt", "UpdatedAt").Where("identity_source_id = ?", identitySource.IdentitySourceID).Updates(&dbIdentitySource)
	}
	if result.RowsAffected == 0 || result.Error != nil {
		pgErr, ok := result.Error.(*pgconn.PgError)
		if ok && pgErr.Code == "23505" {
			return nil, fmt.Errorf("storage: identity source cannot be created because of a duplicated name %w", azerrors.ErrStorageDuplicate)
		}
		return nil, fmt.Errorf("storage: identity source cannot be created. %w", azerrors.ErrStorageGeneric)
	}
	return mapIdentitySourceToAgentIdentitySource(&dbIdentitySource)
}

// CreateIdentitySource creates a new identity source.
func (s PostgresCentralStorageAAP) CreateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertIdentitySource(db, true, identitySource)
}

// UpdateIdentitySource updates an identity source.
func (s PostgresCentralStorageAAP) UpdateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertIdentitySource(db, false, identitySource)
}

// DeleteIdentitySource deletes an identity source.
func (s PostgresCentralStorageAAP) DeleteIdentitySource(accountID int64, identitySourceID string) (*azmodels.IdentitySource, error) {
	if err := validateAccountID("identitysource", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}
	if err := validateUUID("identitysource", identitySourceID); err != nil {
		return nil, fmt.Errorf("storage: invalid identity source id %q. %w", identitySourceID, azerrors.ErrClientID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	var dbIdentitySource IdentitySource
	result := db.Where("account_id = ?", accountID).Where("identity_source_id = ?", identitySourceID).First(&dbIdentitySource)
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("storage: identity source cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	if dbIdentitySource.Name == IdentitySourceDefaultName {
		return nil, fmt.Errorf("storage: default identity source cannot be deleted. %w", azerrors.ErrStorageGeneric)
	}
	result = db.Where("account_id = ?", accountID).Where("identity_source_id = ?", identitySourceID).Delete(dbIdentitySource)
	if result.RowsAffected == 0 || result.Error != nil {
		return nil, fmt.Errorf("storage: identity source cannot be deleted. %w", azerrors.ErrStorageGeneric)
	}
	return mapIdentitySourceToAgentIdentitySource(&dbIdentitySource)
}

// GetAllIdentitySources returns all identity sources.
func (s PostgresCentralStorageAAP) GetAllIdentitySources(accountID int64, fields map[string]any) ([]azmodels.IdentitySource, error) {
	if err := validateAccountID("identitysource", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	var identitySources []IdentitySource
	query := db.Where("account_id = ?", accountID)
	if _, ok := fields[azmodels.FieldIdentitySourceIdentitySourceID]; ok {
		identitySourceID, ok := fields[azmodels.FieldIdentitySourceIdentitySourceID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid identitysource id. %w", azerrors.ErrClientUUID)
		}
		if err := validateUUID("identitysource", identitySourceID); err != nil {
			return nil, fmt.Errorf("storage: invalid identitysource id %q. %w", identitySourceID, azerrors.ErrClientUUID)
		}
		identitySourceID = "%" + identitySourceID + "%"
		query = query.Where("identity_source_id::text LIKE ?", identitySourceID)
	}
	if _, ok := fields[azmodels.FieldIdentitySourceName]; ok {
		name, ok := fields[azmodels.FieldIdentitySourceName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid identitysource name. %w", azerrors.ErrClientName)
		}
		if err := validateName("identitysource", name); err != nil {
			return nil, fmt.Errorf("storage: invalid identitysource name %q. %w", name, azerrors.ErrClientName)
		}
		name = "%" + name + "%"
		query = query.Where("name LIKE ?", name)
	}
	result := query.Find(&identitySources)
	if result.Error != nil {
		return nil, fmt.Errorf("storage: identity source cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	mIdentitySources := make([]azmodels.IdentitySource, len(identitySources))
	for i, a := range identitySources {
		identitySource, err := mapIdentitySourceToAgentIdentitySource(&a)
		if err != nil {
			return nil, err
		}
		mIdentitySources[i] = *identitySource
	}
	return mIdentitySources, nil
}
