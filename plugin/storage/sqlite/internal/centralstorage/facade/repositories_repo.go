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

package facade

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	azvalidators "github.com/permguard/permguard/pkg/agents/storage/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// errorMessageRepositoryInvalidApplicationID is the error message repository invalid application id.
	errorMessageRepositoryInvalidApplicationID = "storage: invalid client input - application id is not valid (id: %d)"
)

// UpsertRepository creates or updates a repository.
func (r *Facade) UpsertRepository(tx *sql.Tx, isCreate bool, repository *Repository) (*Repository, error) {
	if repository == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - repository data is missing or malformed (%s)", LogRepositoryEntry(repository)))
	}
	if err := azvalidators.ValidateCodeID("repository", repository.ApplicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageRepositoryInvalidApplicationID, repository.ApplicationID))
	}
	if !isCreate && azvalidators.ValidateUUID("repository", repository.RepositoryID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - repository id is not valid (%s)", LogRepositoryEntry(repository)))
	}
	if err := azvalidators.ValidateName("repository", repository.Name); err != nil {
		errorMessage := "storage: invalid client input - repository name is not valid (%s)"
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogRepositoryEntry(repository)))
	}

	applicationID := repository.ApplicationID
	repositoryID := repository.RepositoryID
	repositoryName := repository.Name
	var result sql.Result
	var err error
	if isCreate {
		repositoryID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO repositories (application_id, repository_id, name) VALUES (?, ?, ?)", applicationID, repositoryID, repositoryName)
	} else {
		result, err = tx.Exec("UPDATE repositories SET name = ? WHERE application_id = ? and repository_id = ?", repositoryName, applicationID, repositoryID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "application id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s repository - operation '%s-repository' encountered an issue (%s)", action, action, LogRepositoryEntry(repository)), err, params)
	}

	var dbRepository Repository
	err = tx.QueryRow("SELECT application_id, repository_id, created_at, updated_at, name, ref FROM repositories WHERE application_id = ? and repository_id = ?", applicationID, repositoryID).Scan(
		&dbRepository.ApplicationID,
		&dbRepository.RepositoryID,
		&dbRepository.CreatedAt,
		&dbRepository.UpdatedAt,
		&dbRepository.Name,
		&dbRepository.Ref,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve repository - operation 'retrieve-created-repository' encountered an issue (%s)", LogRepositoryEntry(repository)), err)
	}
	return &dbRepository, nil
}

// UpdateRepositoryRef updates the ref of a repository.
func (r *Facade) UpdateRepositoryRef(tx *sql.Tx, applicationID int64, repositoryID, currentRef, newRef string) error {
	if err := azvalidators.ValidateCodeID("repository", applicationID); err != nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageRepositoryInvalidApplicationID, applicationID))
	}
	if err := azvalidators.ValidateUUID("repository", repositoryID); err != nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - repository id is not valid (id: %s)", repositoryID))
	}
	if err := azvalidators.ValidateSHA256("repository", currentRef); err != nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - current ref is not valid (ref: %s)", currentRef))
	}
	if err := azvalidators.ValidateSHA256("repository", newRef); err != nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - new ref is not valid (ref: %s)", newRef))
	}

	var dbCurrentRef string
	err := tx.QueryRow("SELECT ref FROM repositories WHERE application_id = ? AND repository_id = ?", applicationID, repositoryID).Scan(&dbCurrentRef)
	if err != nil {
		if err == sql.ErrNoRows {
			return azerrors.WrapSystemError(azerrors.ErrClientNotFound, fmt.Sprintf("repository not found (application_id: %d, repository_id: %s)", applicationID, repositoryID))
		}
		return WrapSqlite3Error("failed to retrieve current ref for repository", err)
	}

	if dbCurrentRef != currentRef {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("current ref mismatch (expected: %s, got: %s)", dbCurrentRef, currentRef))
	}

	result, err := tx.Exec("UPDATE repositories SET ref = ? WHERE application_id = ? AND repository_id = ?", newRef, applicationID, repositoryID)
	if err != nil {
		return WrapSqlite3Error("failed to update repository ref", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return WrapSqlite3Error("failed to get rows affected for update ref", err)
	}
	if rows != 1 {
		return azerrors.WrapSystemError(azerrors.ErrClientUpdateConflict, fmt.Sprintf("update failed, no rows affected (application_id: %d, repository_id: %s)", applicationID, repositoryID))
	}
	return nil
}

// DeleteRepository deletes a repository.
func (r *Facade) DeleteRepository(tx *sql.Tx, applicationID int64, repositoryID string) (*Repository, error) {
	if err := azvalidators.ValidateCodeID("repository", applicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageRepositoryInvalidApplicationID, applicationID))
	}
	if err := azvalidators.ValidateUUID("repository", repositoryID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - repository id is not valid (id: %s)", repositoryID))
	}

	var dbRepository Repository
	err := tx.QueryRow("SELECT application_id, repository_id, created_at, updated_at, name, ref FROM repositories WHERE application_id = ? and repository_id = ?", applicationID, repositoryID).Scan(
		&dbRepository.ApplicationID,
		&dbRepository.RepositoryID,
		&dbRepository.CreatedAt,
		&dbRepository.UpdatedAt,
		&dbRepository.Name,
		&dbRepository.Ref,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - repository id is not valid (id: %s)", repositoryID), err)
	}
	res, err := tx.Exec("DELETE FROM repositories WHERE application_id = ? and repository_id = ?", applicationID, repositoryID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete repository - operation 'delete-repository' encountered an issue (id: %s)", repositoryID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete repository - operation 'delete-repository' could not find the repository (id: %s)", repositoryID), err)
	}
	return &dbRepository, nil
}

// FetchRepositories retrieves repositories.
func (r *Facade) FetchRepositories(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]Repository, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	if err := azvalidators.ValidateCodeID("repository", applicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf(errorMessageRepositoryInvalidApplicationID, applicationID))
	}

	var dbRepositories []Repository

	baseQuery := "SELECT * FROM repositories"
	var conditions []string
	var args []any

	conditions = append(conditions, "application_id = ?")
	args = append(args, applicationID)

	if filterID != nil {
		repositoryID := *filterID
		if err := azvalidators.ValidateUUID("repository", repositoryID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - repository id is not valid (id: %s)", repositoryID))
		}
		conditions = append(conditions, "repository_id = ?")
		args = append(args, repositoryID)
	}

	if filterName != nil {
		repositoryName := *filterName
		if err := azvalidators.ValidateName("repository", repositoryName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - repository name is not valid (name: %s)", repositoryName))
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
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve repositories - operation 'retrieve-repositories' encountered an issue with parameters %v", args), err)
	}

	return dbRepositories, nil
}
