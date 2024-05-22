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
	RepositoryDefaultName = "default"
)

// CreateRepository creates a new repository.
func (s PostgresCentralStoragePAP) upsertRepository(db *gorm.DB, isTransaction bool, isCreate bool, repository *azmodels.Repository) (*azmodels.Repository, error) {
	if repository == nil {
		return nil, fmt.Errorf("storage: %w", azerrors.ErrInvalidInputParameter)
	}
	if err := validateAccountID("repository", repository.AccountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", repository.AccountID, azerrors.ErrClientAccountID)
	}
	if err := validateName("repository", repository.Name); err != nil {
		return nil, fmt.Errorf("storage: invalid repository name %q. %w", repository.Name, azerrors.ErrClientName)
	}
	if !isCreate && repository.Name == RepositoryDefaultName {
		return nil, fmt.Errorf("storage: repository cannot be updated with a default name. %w", azerrors.ErrClientName)
	}

	var dbRepository Repository
	var result *gorm.DB
	if isCreate {
		dbRepository = Repository{
			AccountID: repository.AccountID,
			Name:      repository.Name,
		}
		tx := db
		if !isTransaction {
			tx = db.Begin()
		}
		result = db.Omit("CreatedAt", "UpdatedAt").Create(&dbRepository)
		if result.RowsAffected == 0 || result.Error != nil {
			pgErr, ok := result.Error.(*pgconn.PgError)
			if ok && pgErr.Code == "23505" {
				return nil, fmt.Errorf("storage: repository cannot be created because of a duplicated name %w", azerrors.ErrStorageDuplicate)
			}
			return nil, fmt.Errorf("storage: repository cannot be created. %w", azerrors.ErrStorageGeneric)
		}
		_, err := s.createSchema(tx, dbRepository.AccountID, dbRepository.RepositoryID)
		if err != nil {
			if isTransaction {
				tx.Rollback()
			}
			return nil, err
		}
		if !isTransaction {
			tx.Commit()
		}
	} else {
		result = db.Where("account_id = ?", repository.AccountID).Where("identity_source_id = ?", repository.RepositoryID).First(&dbRepository)
		if result.RowsAffected == 0 {
			return nil, fmt.Errorf("storage: repository cannot be retrieved. %w", azerrors.ErrStorageNotFound)
		}
		dbRepository.Name = repository.Name
		result = db.Omit("CreatedAt", "UpdatedAt").Where("identity_source_id = ?", repository.RepositoryID).Updates(&dbRepository)
	}
	if result.RowsAffected == 0 || result.Error != nil {
		pgErr, ok := result.Error.(*pgconn.PgError)
		if ok && pgErr.Code == "23505" {
			return nil, fmt.Errorf("storage: repository cannot be created because of a duplicated name %w", azerrors.ErrStorageDuplicate)
		}
		return nil, fmt.Errorf("storage: repository cannot be created. %w", azerrors.ErrStorageGeneric)
	}
	return mapRepositoryToAgentRepository(&dbRepository)
}

// CreateRepository creates a new repository.
func (s PostgresCentralStoragePAP) CreateRepository(repository *azmodels.Repository) (*azmodels.Repository, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertRepository(db, false, true, repository)
}

// UpdateRepository updates an repository.
func (s PostgresCentralStoragePAP) UpdateRepository(repository *azmodels.Repository) (*azmodels.Repository, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertRepository(db, false, false, repository)
}

// DeleteRepository deletes an repository.
func (s PostgresCentralStoragePAP) DeleteRepository(accountID int64, repositoryID string) (*azmodels.Repository, error) {
	if err := validateAccountID("repository", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}
	if err := validateUUID("repository", repositoryID); err != nil {
		return nil, fmt.Errorf("storage: invalid repository id %q. %w", repositoryID, azerrors.ErrClientID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	var dbRepository Repository
	result := db.Where("account_id = ?", accountID).Where("identity_source_id = ?", repositoryID).First(&dbRepository)
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("storage: repository cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	if dbRepository.Name == RepositoryDefaultName {
		return nil, fmt.Errorf("storage: default repository cannot be deleted. %w", azerrors.ErrStorageGeneric)
	}
	result = db.Where("account_id = ?", accountID).Where("identity_source_id = ?", repositoryID).Delete(dbRepository)
	if result.RowsAffected == 0 || result.Error != nil {
		return nil, fmt.Errorf("storage: repository cannot be deleted. %w", azerrors.ErrStorageGeneric)
	}
	return mapRepositoryToAgentRepository(&dbRepository)
}

// GetAllRepositories returns all repositories.
func (s PostgresCentralStoragePAP) GetAllRepositories(accountID int64, fields map[string]any) ([]azmodels.Repository, error) {
	if err := validateAccountID("repository", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	var repositories []Repository
	query := db.Where("account_id = ?", accountID)
	if _, ok := fields[azmodels.FieldRepositoryRepositoryID]; ok {
		repositoryID, ok := fields[azmodels.FieldRepositoryRepositoryID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid repository id. %w", azerrors.ErrClientUUID)
		}
		if err := validateUUID("repository", repositoryID); err != nil {
			return nil, fmt.Errorf("storage: invalid repository id %q. %w", repositoryID, azerrors.ErrClientUUID)
		}
		repositoryID = "%" + repositoryID + "%"
		query = query.Where("identity_source_id::text LIKE ?", repositoryID)
	}
	if _, ok := fields[azmodels.FieldRepositoryName]; ok {
		name, ok := fields[azmodels.FieldRepositoryName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid repository name. %w", azerrors.ErrClientName)
		}
		if err := validateName("repository", name); err != nil {
			return nil, fmt.Errorf("storage: invalid repository name %q. %w", name, azerrors.ErrClientName)
		}
		name = "%" + name + "%"
		query = query.Where("name LIKE ?", name)
	}
	result := query.Find(&repositories)
	if result.Error != nil {
		return nil, fmt.Errorf("storage: repository cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	mRepositories := make([]azmodels.Repository, len(repositories))
	for i, a := range repositories {
		repository, err := mapRepositoryToAgentRepository(&a)
		if err != nil {
			return nil, err
		}
		mRepositories[i] = *repository
	}
	return mRepositories, nil
}
