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
	"math/rand"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	azvalidators "github.com/permguard/permguard/pkg/agents/storage/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// GenerateApplicationID generates a random application id.
func GenerateApplicationID() int64 {
	const base = 100000000000
	const maxRange = 900000000000
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := r.Int63n(maxRange)
	applicationID := base + randomNumber
	return applicationID
}

// UpsertApplication creates or updates an application.
func (r *Facade) UpsertApplication(tx *sql.Tx, isCreate bool, application *Application) (*Application, error) {
	if application == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - application data is missing or malformed (%s)", LogApplicationEntry(application)))
	}
	if !isCreate && azvalidators.ValidateCodeID("application", application.ApplicationID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - application id is not valid (%s)", LogApplicationEntry(application)))
	}
	if err := azvalidators.ValidateName("application", application.Name); err != nil {
		errorMessage := "storage: invalid client input - application name is not valid (%s)"
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogApplicationEntry(application)))
	}

	applicationID := application.ApplicationID
	applicationName := application.Name
	var result sql.Result
	var err error
	if isCreate {
		applicationID = GenerateApplicationID()
		result, err = tx.Exec("INSERT INTO applications (application_id, name) VALUES (?, ?)", applicationID, applicationName)
	} else {
		result, err = tx.Exec("UPDATE applications SET name = ? WHERE application_id = ?", applicationName, applicationID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to %s application - operation '%s-application' encountered an issue (%s)", action, action, LogApplicationEntry(application)), err)
	}

	var dbApplication Application
	err = tx.QueryRow("SELECT application_id, created_at, updated_at, name FROM applications WHERE application_id = ?", applicationID).Scan(
		&dbApplication.ApplicationID,
		&dbApplication.CreatedAt,
		&dbApplication.UpdatedAt,
		&dbApplication.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve application - operation 'retrieve-created-application' encountered an issue (%s)", LogApplicationEntry(application)), err)
	}
	return &dbApplication, nil
}

// DeleteApplication deletes an application.
func (r *Facade) DeleteApplication(tx *sql.Tx, applicationID int64) (*Application, error) {
	if err := azvalidators.ValidateCodeID("application", applicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - application id is not valid (id: %d)", applicationID))
	}

	var dbApplication Application
	err := tx.QueryRow("SELECT application_id, created_at, updated_at, name FROM applications WHERE application_id = ?", applicationID).Scan(
		&dbApplication.ApplicationID,
		&dbApplication.CreatedAt,
		&dbApplication.UpdatedAt,
		&dbApplication.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - application id is not valid (id: %d)", applicationID), err)
	}
	res, err := tx.Exec("DELETE FROM applications WHERE application_id = ?", applicationID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete application - operation 'delete-application' encountered an issue (id: %d)", applicationID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete application - operation 'delete-application' encountered an issue (id: %d)", applicationID), err)
	}
	return &dbApplication, nil
}

// FetchApplications retrieves applications.
func (r *Facade) FetchApplications(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]Application, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	var dbApplications []Application

	baseQuery := "SELECT * FROM applications"
	var conditions []string
	var args []any

	if filterID != nil {
		applicationID := *filterID
		if err := azvalidators.ValidateCodeID("application", applicationID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - application id is not valid (id: %d)", applicationID))
		}
		conditions = append(conditions, "application_id = ?")
		args = append(args, applicationID)
	}

	if filterName != nil {
		applicationName := *filterName
		if err := azvalidators.ValidateName("application", applicationName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - application name is not valid (name: %s)", applicationName))
		}
		applicationName = "%" + applicationName + "%"
		conditions = append(conditions, "name LIKE ?")
		args = append(args, applicationName)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY application_id ASC"

	limit := pageSize
	offset := (page - 1) * pageSize
	baseQuery += " LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	err := db.Select(&dbApplications, baseQuery, args...)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve applications - operation 'retrieve-applications' encountered an issue with parameters %v", args), err)
	}

	return dbApplications, nil
}
