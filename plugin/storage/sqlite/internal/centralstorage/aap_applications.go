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

// CreateApplication creates a new application.
func (s SQLiteCentralStorageAAP) CreateApplication(application *azmodelaap.Application) (*azmodelaap.Application, error) {
	if application == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, " invalid client input - application is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInApplication := &azirepos.Application{
		ApplicationID: application.ApplicationID,
		Name:          application.Name,
	}
	dbOutApplication, err := s.sqlRepo.UpsertApplication(tx, true, dbInApplication)
	if s.config.GetEnabledDefaultCreation() {
		if err == nil {
			tenant := &azirepos.Tenant{
				ApplicationID: dbOutApplication.ApplicationID,
				Name:          TenantDefaultName,
			}
			_, err = s.sqlRepo.UpsertTenant(tx, true, tenant)
		}
		if err == nil {
			identitySource := &azirepos.IdentitySource{
				ApplicationID: dbOutApplication.ApplicationID,
				Name:          IdentitySourceDefaultName,
			}
			_, err = s.sqlRepo.UpsertIdentitySource(tx, true, identitySource)
		}
		if err == nil {
			ledger := &azirepos.Ledger{
				ApplicationID: dbOutApplication.ApplicationID,
				Name:          LedgerDefaultName,
			}
			_, err = s.sqlRepo.UpsertLedger(tx, true, ledger)
		}
	}
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapApplicationToAgentApplication(dbOutApplication)
}

// UpdateApplication updates an application.
func (s SQLiteCentralStorageAAP) UpdateApplication(application *azmodelaap.Application) (*azmodelaap.Application, error) {
	if application == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, " invalid client input - application is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInApplication := &azirepos.Application{
		ApplicationID: application.ApplicationID,
		Name:          application.Name,
	}
	dbOutapplication, err := s.sqlRepo.UpsertApplication(tx, false, dbInApplication)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapApplicationToAgentApplication(dbOutapplication)
}

// DeleteApplication deletes an application.
func (s SQLiteCentralStorageAAP) DeleteApplication(applicationID int64) (*azmodelaap.Application, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutapplication, err := s.sqlRepo.DeleteApplication(tx, applicationID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapApplicationToAgentApplication(dbOutapplication)
}

// FetchApplications returns all applications.
func (s SQLiteCentralStorageAAP) FetchApplications(page int32, pageSize int32, fields map[string]any) ([]azmodelaap.Application, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.GetDataFetchMaxPageSize() {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientPagination, fmt.Sprintf(" invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *int64
	if _, ok := fields[azmodelaap.FieldApplicationApplicationID]; ok {
		applicationID, ok := fields[azmodelaap.FieldApplicationApplicationID].(int64)
		if !ok {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf(" invalid client input - application id is not valid (application id: %d)", applicationID))
		}
		filterID = &applicationID
	}
	var filterName *string
	if _, ok := fields[azmodelaap.FieldApplicationName]; ok {
		applicationName, ok := fields[azmodelaap.FieldApplicationName].(string)
		if !ok {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf(" invalid client input - application name is not valid (application name: %s)", applicationName))
		}
		filterName = &applicationName
	}
	dbApplications, err := s.sqlRepo.FetchApplications(db, page, pageSize, filterID, filterName)
	if err != nil {
		return nil, err
	}
	applications := make([]azmodelaap.Application, len(dbApplications))
	for i, a := range dbApplications {
		application, err := mapApplicationToAgentApplication(&a)
		if err != nil {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageEntityMapping, fmt.Sprintf(" failed to convert application entity (%s)", azirepos.LogApplicationEntry(&a)))
		}
		applications[i] = *application
	}
	return applications, nil
}
