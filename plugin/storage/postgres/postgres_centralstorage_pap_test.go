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
	"database/sql"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/stretchr/testify/assert"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azrtmmocks "github.com/permguard/permguard/pkg/agents/runtime/mocks"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// newPostgresCentralStoragePAPMock creates a new PAPCentralStorage with a mock sql.DB and gorm.DB.
func newPostgresCentralStoragePAPMock(t *testing.T) (azstorage.PAPCentralStorage, *sql.DB, *gorm.DB, sqlmock.Sqlmock) {
	runtimeCtx := azrtmmocks.NewRuntimeContextMock()
	storageCtx, err := azstorage.NewStorageContext(runtimeCtx, azstorage.StoragePostgres)
	if err != nil {
		t.Fatal(err)
	}
	pgConn, sqlDB, gormDB, mock := newPostgresConnectionMock(t)
	storage, err := newPostgresCentralStorage(storageCtx, pgConn)
	if err != nil {
		t.Fatal(err)
	}
	papStorage, err := storage.GetPAPCentralStorage()
	if err != nil {
		t.Fatal(err)
	}
	return papStorage, sqlDB, gormDB, mock
}

// registerRepositoryForInsertMocking registers an repository for insert mocking.
func registerRepositoryForInsertMocking(account *azmodels.Account, name string) (*azmodels.Repository, string, *sqlmock.Rows) {
	if name == "" {
		name = "repoa"
	}
	repository := &azmodels.Repository{
		RepositoryID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "INSERT INTO \"repositories\" (.+) VALUES (.+)"
	sqlRows := sqlmock.NewRows([]string{"repository_id", "created_at", "updated_at", "account_id", "name"}).
		AddRow(repository.RepositoryID, repository.CreatedAt, repository.UpdatedAt, repository.AccountID, repository.Name)
	return repository, sql, sqlRows
}

// registerRepositoryForUpdateMocking register an repository for update mocking.
func registerRepositoryForUpdateMocking(account *azmodels.Account, name string) (*azmodels.Repository, string, *sqlmock.Rows, driver.Result) {
	if name == "" {
		name = "repoa"
	}
	repository := &azmodels.Repository{
		RepositoryID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "UPDATE \"repositories\" .+"
	sqlRows := sqlmock.NewRows([]string{"repository_id", "account_id", "created_at", "updated_at", "name"}).
		AddRow(repository.RepositoryID, repository.AccountID, repository.CreatedAt, repository.UpdatedAt, repository.Name)
	sqlResult := sqlmock.NewResult(repository.AccountID, 1)
	return repository, sql, sqlRows, sqlResult
}

// registerRepositoryForDeleteMocking register an repository for delete mocking.
func registerRepositoryForDeleteMocking(account *azmodels.Account, name string) (*azmodels.Repository, string, *sqlmock.Rows, driver.Result) {
	if name == "" {
		name = "repoa"
	}
	repository := &azmodels.Repository{
		RepositoryID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "DELETE FROM \"repositories\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"repository_id", "account_id", "created_at", "updated_at", "name"}).
		AddRow(repository.RepositoryID, repository.AccountID, repository.CreatedAt, repository.UpdatedAt, repository.Name)
	sqlResult := sqlmock.NewResult(repository.AccountID, 1)
	return repository, sql, sqlRows, sqlResult
}

// registerRepositoryForGetAllMocking registers the mocking for the GetAll method of the RepositoryRepository
func registerRepositoryForGetAllMocking() ([]azmodels.Repository, string, *sqlmock.Rows) {
	repositories := []azmodels.Repository {
		{
			RepositoryID: "1609037a-0c69-4568-ba2a-792f90fc000f",
			AccountID: 581616507495,
			Name: "repoa1",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			RepositoryID: "24f378b2-f12f-4a45-90a2-81bfa7e98229",
			AccountID: 673389447445,
			Name: "repoa2",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	sql := "SELECT .+ FROM \"repositories\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"repository_id", "created_at", "updated_at", "account_id", "name"})
	for _, repository := range repositories {
		sqlRows  = sqlRows.AddRow(repository.RepositoryID, repository.CreatedAt, repository.UpdatedAt, repository.AccountID, repository.Name)
	}
	return repositories, sql, sqlRows
}

// registerSchemaForInsertMocking registers an schema for insert mocking.
func registerSchemaForInsertMocking(account *azmodels.Account) (*azmodels.Schema, string, *sqlmock.Rows) {
	schema := &azmodels.Schema{
		SchemaID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
	}
	sql := "INSERT INTO \"schemas\" .+"
	sqlRows := sqlmock.NewRows([]string{"schema_id", "created_at", "updated_at", "account_id"}).
		AddRow(schema.SchemaID, schema.CreatedAt, schema.UpdatedAt, schema.AccountID)
	return schema, sql, sqlRows
}

// registerSchemaForUpdateMocking register an schema for update mocking.
func registerSchemaForUpdateMocking(account *azmodels.Account) (*azmodels.Schema, string, *sqlmock.Rows, driver.Result) {
	schemaDomains := azmodels.SchemaDomains{
		Domains: []azmodels.Domain{
			{
				Name:        "domain1",
				Description: "domain1",
				Resources: []azmodels.Resource{
					{
						Name:        "resource1",
						Description: "resource1",
						Actions: []azmodels.Action{
							{
								Name:        "action1",
								Description: "action1",
							},
						},
					},
				},
			},
		},
	}
	schema := &azmodels.Schema{
		SchemaID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		SchemaDomains: &schemaDomains,
	}
	sql := "UPDATE \"schemas\" .+"
	sqlRows := sqlmock.NewRows([]string{"schema_id", "account_id", "created_at", "updated_at", "repository_id"}).
		AddRow(schema.SchemaID, schema.AccountID, schema.CreatedAt, schema.UpdatedAt, schema.RepositoryID)
	sqlResult := sqlmock.NewResult(schema.AccountID, 1)
	return schema, sql, sqlRows, sqlResult
}

// registerSchemaForDeleteMocking register an schema for delete mocking.
func registerSchemaForDeleteMocking(account *azmodels.Account) (*azmodels.Schema, string, *sqlmock.Rows, driver.Result) {
	schema := &azmodels.Schema{
		SchemaID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
	}
	sql := "DELETE FROM \"schemas\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"schema_id", "account_id", "created_at", "updated_at"}).
		AddRow(schema.SchemaID, schema.AccountID, schema.CreatedAt, schema.UpdatedAt)
	sqlResult := sqlmock.NewResult(schema.AccountID, 1)
	return schema, sql, sqlRows, sqlResult
}

// registerSchemaForGetAllMocking registers the mocking for the GetAll method of the SchemaSchema
func registerSchemaForGetAllMocking() ([]azmodels.Schema, string, *sqlmock.Rows) {
	schemas := []azmodels.Schema {
		{
			SchemaID: "1609037a-0c69-4568-ba2a-792f90fc000f",
			AccountID: 581616507495,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			SchemaID: "24f378b2-f12f-4a45-90a2-81bfa7e98229",
			AccountID: 673389447445,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	sql := "SELECT .+ FROM \"schemas\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"schema_id", "created_at", "updated_at", "account_id"})
	for _, schema := range schemas {
		sqlRows  = sqlRows.AddRow(schema.SchemaID, schema.CreatedAt, schema.UpdatedAt, schema.AccountID)
	}
	return schemas, sql, sqlRows
}

// TestNewPostgresPAPCentralStorage tests the newPostgresPAPCentralStorage function.
func TestNewPostgresPAPCentralStorage(t *testing.T) {
	assert := assert.New(t)

	runtimeCtx := azrtmmocks.NewRuntimeContextMock()
	storageCtx, err := azstorage.NewStorageContext(runtimeCtx, azstorage.StoragePostgres)
	if err != nil {
		t.Fatal(err)
	}
	pgConn, _, _, _ := newPostgresConnectionMock(t)

	storage, err := newPostgresPAPCentralStorage(nil, nil)
	azerrors.IsSystemError(err)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrInvalidInputParameter, err), "error should be ErrInvalidInputParameter")

	storage, err = newPostgresPAPCentralStorage(storageCtx, nil)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrInvalidInputParameter, err), "error should be ErrInvalidInputParameter")

	storage, err = newPostgresPAPCentralStorage(nil, pgConn)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrInvalidInputParameter, err), "error should be ErrInvalidInputParameter")

	storage, err = newPostgresPAPCentralStorage(storageCtx, pgConn)
	assert.NotNil(storage, "storage should not be nil")
	assert.Nil(err, "error should be nil")
}
