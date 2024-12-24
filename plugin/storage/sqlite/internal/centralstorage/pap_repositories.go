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

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

const (
	RepositoryDefaultName = "default"
)

// CreateRepository creates a new repository.
func (s SQLiteCentralStoragePAP) CreateRepository(repository *azmodels.Repository) (*azmodels.Repository, error) {
	if repository == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - repository is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInRepository := &azirepos.Repository{
		ApplicationID: repository.ApplicationID,
		Name:          repository.Name,
	}
	dbOutRepository, err := s.sqlRepo.UpsertRepository(tx, true, dbInRepository)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapRepositoryToAgentRepository(dbOutRepository)
}

// UpdateRepository updates a repository.
func (s SQLiteCentralStoragePAP) UpdateRepository(repository *azmodels.Repository) (*azmodels.Repository, error) {
	if repository == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - repository is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInRepository := &azirepos.Repository{
		RepositoryID:  repository.RepositoryID,
		ApplicationID: repository.ApplicationID,
		Name:          repository.Name,
	}
	dbOutRepository, err := s.sqlRepo.UpsertRepository(tx, false, dbInRepository)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapRepositoryToAgentRepository(dbOutRepository)
}

// DeleteRepository deletes a repository.
func (s SQLiteCentralStoragePAP) DeleteRepository(applicationID int64, repositoryID string) (*azmodels.Repository, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutRepository, err := s.sqlRepo.DeleteRepository(tx, applicationID, repositoryID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapRepositoryToAgentRepository(dbOutRepository)
}

// FetchRepositories returns all repositories.
func (s SQLiteCentralStoragePAP) FetchRepositories(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodels.Repository, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.GetDataFetchMaxPageSize() {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *string
	if _, ok := fields[azmodels.FieldRepositoryRepositoryID]; ok {
		repositoryID, ok := fields[azmodels.FieldRepositoryRepositoryID].(string)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - repository id is not valid (repository id: %s)", repositoryID))
		}
		filterID = &repositoryID
	}
	var filterName *string
	if _, ok := fields[azmodels.FieldRepositoryName]; ok {
		repositoryName, ok := fields[azmodels.FieldRepositoryName].(string)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - repository name is not valid (repository name: %s)", repositoryName))
		}
		filterName = &repositoryName
	}
	dbRepositories, err := s.sqlRepo.FetchRepositories(db, page, pageSize, applicationID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	repositories := make([]azmodels.Repository, len(dbRepositories))
	for i, a := range dbRepositories {
		repository, err := mapRepositoryToAgentRepository(&a)
		if err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrStorageEntityMapping, fmt.Sprintf("storage: failed to convert repository entity (%s)", azirepos.LogRepositoryEntry(&a)))
		}
		repositories[i] = *repository
	}
	return repositories, nil
}
