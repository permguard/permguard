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

package repositories

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azivalidators "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/validators"
)

const (
	// errorMessageRepositoryInvalidAccountID is the error message repository invalid account id.
	errorMessageRepositoryInvalidAccountID = "storage: invalid client input - account id is not valid (id: %d)."
)

// UpsertRepository creates or updates a repository.
func (r *Repo) UpsertRepository(tx *sql.Tx, isCreate bool, repository *Repository) (*Repository, error) {
	if repository == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - repository data is missing or malformed (%s).", LogRepositoryEntry(repository)))
	}
	if err := azivalidators.ValidateAccountID("repository", repository.AccountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageRepositoryInvalidAccountID, repository.AccountID))
	}
	if !isCreate && azivalidators.ValidateUUID("repository", repository.RepositoryID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - repository id is not valid (%s).", LogRepositoryEntry(repository)))
	}
	if err := azivalidators.ValidateName("repository", repository.Name); err != nil {
		errorMessage := "storage: invalid client input - repository name is not valid (%s)."
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogRepositoryEntry(repository)))
	}

	accountID := repository.AccountID
	repositoryID := repository.RepositoryID
	repositoryName := repository.Name
	var result sql.Result
	var err error
	if isCreate {
		repositoryID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO repositories (account_id, repository_id, name) VALUES (?, ?, ?)", accountID, repositoryID, repositoryName)
	} else {
		result, err = tx.Exec("UPDATE repositories SET name = ? WHERE account_id = ? and repository_id = ?", repositoryName, accountID, repositoryID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "account id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s repository - operation '%s-repository' encountered an issue (%s).", action, action, LogRepositoryEntry(repository)), err, params)
	}

	var dbRepository Repository
	err = tx.QueryRow("SELECT account_id, repository_id, created_at, updated_at, name FROM repositories WHERE account_id = ? and repository_id = ?", accountID, repositoryID).Scan(
		&dbRepository.AccountID,
		&dbRepository.RepositoryID,
		&dbRepository.CreatedAt,
		&dbRepository.UpdatedAt,
		&dbRepository.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve repository - operation 'retrieve-created-repository' encountered an issue (%s).", LogRepositoryEntry(repository)), err)
	}
	return &dbRepository, nil
}

// DeleteRepository deletes a repository.
func (r *Repo) DeleteRepository(tx *sql.Tx, accountID int64, repositoryID string) (*Repository, error) {
	if err := azivalidators.ValidateAccountID("repository", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageRepositoryInvalidAccountID, accountID))
	}
	if err := azivalidators.ValidateUUID("repository", repositoryID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - repository id is not valid (id: %s).", repositoryID))
	}

	var dbRepository Repository
	err := tx.QueryRow("SELECT account_id, repository_id, created_at, updated_at, name FROM repositories WHERE account_id = ? and repository_id = ?", accountID, repositoryID).Scan(
		&dbRepository.AccountID,
		&dbRepository.RepositoryID,
		&dbRepository.CreatedAt,
		&dbRepository.UpdatedAt,
		&dbRepository.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - repository id is not valid (id: %s).", repositoryID), err)
	}
	res, err := tx.Exec("DELETE FROM repositories WHERE account_id = ? and repository_id = ?", accountID, repositoryID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete repository - operation 'delete-repository' encountered an issue (id: %s).", repositoryID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete repository - operation 'delete-repository' could not find the repository (id: %s).", repositoryID), err)
	}
	return &dbRepository, nil
}

// FetchRepositories retrieves repositories.
func (r *Repo) FetchRepositories(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]Repository, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid.", page, pageSize))
	}
	if err := azivalidators.ValidateAccountID("repository", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf(errorMessageRepositoryInvalidAccountID, accountID))
	}

	var dbRepositories []Repository

	baseQuery := "SELECT * FROM repositories"
	var conditions []string
	var args []interface{}

	conditions = append(conditions, "account_id = ?")
	args = append(args, accountID)

	if filterID != nil {
		repositoryID := *filterID
		if err := azivalidators.ValidateUUID("repository", repositoryID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - repository id is not valid (id: %s).", repositoryID))
		}
		conditions = append(conditions, "repository_id = ?")
		args = append(args, repositoryID)
	}

	if filterName != nil {
		repositoryName := *filterName
		if err := azivalidators.ValidateName("repository", repositoryName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - repository name is not valid (name: %s).", repositoryName))
		}
		repositoryName = "%" + repositoryName + "%"
		conditions = append(conditions, "name LIKE ?")
		args = append(args, repositoryName)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY repository_id ASC"

	limit := pageSize
	offset := (page - 1) * pageSize
	baseQuery += " LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	err := db.Select(&dbRepositories, baseQuery, args...)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve repositories - operation 'retrieve-repositories' encountered an issue with parameters %v.", args), err)
	}

	return dbRepositories, nil
}
