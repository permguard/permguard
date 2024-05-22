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
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// TestPAPUpdateSchemasWithInvalidInputs tests the update of an schema with invalid inputs.
func TestPAPUpdateSchemasWithInvalidInputs(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	schema, _, _, _ := registerSchemaForUpdateMocking(account)

	inputSchema := &azmodels.Schema{
		SchemaID:       schema.SchemaID,
		AccountID: 		-1,
		RepositoryID:   schema.RepositoryID,
		RepositoryName: schema.RepositoryName,
		SchemaDomains:  schema.SchemaDomains,
	}
	outputSchema, err := storage.UpdateSchema(inputSchema)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(outputSchema, "accounts should be nil")

	inputSchema.SchemaID = "not valid"
	inputSchema.AccountID = schema.AccountID
	outputSchema, err = storage.UpdateSchema(inputSchema)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientUUID")
	assert.Nil(outputSchema, "accounts should be nil")


	inputSchema.SchemaID = schema.SchemaID
	inputSchema.AccountID = schema.AccountID
	inputSchema.SchemaDomains.Domains = nil
	outputSchema, err = storage.UpdateSchema(inputSchema)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientGeneric, err), "error should be ErrClientGeneric")
	assert.Nil(outputSchema, "accounts should be nil")
}

// TestPAPUpdateFailingSchemasWithNotExistingSchemaWithSchemaID tests the update of a schema without a schema ID.
func TestPAPUpdateFailingSchemasWithNotExistingSchemaWithSchemaID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	schema, _, _, _ := registerSchemaForUpdateMocking(account)

	accountsSQLSelect := "SELECT .+ FROM \"schemas\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnError(errors.New("something bad has happened"))

	inputSchema := &azmodels.Schema{
		SchemaID:       schema.SchemaID,
		AccountID: 		schema.AccountID,
		RepositoryID:   schema.RepositoryID,
		RepositoryName: schema.RepositoryName,
		SchemaDomains:  schema.SchemaDomains,
	}
	outputSchema, err := storage.UpdateSchema(inputSchema)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputSchema, "schema should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

// TestPAPUpdateSchemaWithADuplicateError tests the update of a schema with a duplicate error.
func TestPAPUpdateSchemaWithADuplicateError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	schema, schemaSQL, sqlSchemas, _ := registerSchemaForUpdateMocking(account)

	accountsSQLSelect := "SELECT .+ FROM \"schemas\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlSchemas)
	mock.ExpectBegin()
	mock.ExpectExec(schemaSQL).WillReturnError(&pgconn.PgError{ Code: "23505" })
	mock.ExpectRollback()

	inputSchema := &azmodels.Schema{
		SchemaID:       schema.SchemaID,
		AccountID: 		schema.AccountID,
		RepositoryID:   schema.RepositoryID,
		RepositoryName: schema.RepositoryName,
		SchemaDomains:  schema.SchemaDomains,
	}
	outputSchema, err := storage.UpdateSchema(inputSchema)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputSchema, "schema should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageDuplicate, err), "error should be ErrStorageDuplicate")
}

// TestPAPUpdateSchemaWithAGenericError tests the update of a schema with a generic error.
func TestPAPUpdateSchemaWithAGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	schema, schemaSQL, sqlSchemas, _ := registerSchemaForUpdateMocking(account)

	accountsSQLSelect := "SELECT .+ FROM \"schemas\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlSchemas)
	mock.ExpectBegin()
	mock.ExpectExec(schemaSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputSchema := &azmodels.Schema{
		SchemaID:       schema.SchemaID,
		AccountID: 		schema.AccountID,
		RepositoryID:   schema.RepositoryID,
		RepositoryName: schema.RepositoryName,
		SchemaDomains:  schema.SchemaDomains,
	}
	outputSchema, err := storage.UpdateSchema(inputSchema)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputSchema, "schema should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

// TestPAPUpdateSchemaWithSuccess tests the update of a schema with success.
func TestPAPUpdateSchemaWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	schema, schemaSQL, sqlSchemas, sqlSchemaResult := registerSchemaForUpdateMocking(account)

	accountsSQLSelect := "SELECT .+ FROM \"schemas\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlSchemas)
	mock.ExpectBegin()
	mock.ExpectExec(schemaSQL).WillReturnResult(sqlSchemaResult)
	mock.ExpectCommit()

	inputSchema := &azmodels.Schema{
		SchemaID:       schema.SchemaID,
		AccountID: 		schema.AccountID,
		RepositoryID:   schema.RepositoryID,
		RepositoryName: schema.RepositoryName,
		SchemaDomains:  schema.SchemaDomains,
	}
	outputSchema, err := storage.UpdateSchema(inputSchema)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputSchema, "schema should be not nil")
	assert.Equal(schema.SchemaID, outputSchema.SchemaID, "schema id is not correct")
	assert.Equal(schema.AccountID, outputSchema.AccountID, "schema account id is not correct")
	assert.Nil(err, "error should be nil")
}

// TestPAPGetAllSchemasWithInvalidInputs tests the get all schemas with invalid inputs.
func TestPAPGetAllSchemasWithInvalidInputs(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	//_, _, _, _ := registerSchemaForUpdateMocking(account)

	outputSchemas, err := storage.GetAllSchemas(-1, nil)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(outputSchemas, "accounts should be nil")

	inputMap := map[string]interface{}{
		azmodels.FieldSchemaSchemaID: 1,
	}
	outputSchemas, err = storage.GetAllSchemas(account.AccountID, inputMap)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientAccountID")
	assert.Nil(outputSchemas, "accounts should be nil")

	inputMap = map[string]interface{}{
		azmodels.FieldSchemaSchemaID: "not valid",
	}
	outputSchemas, err = storage.GetAllSchemas(account.AccountID, inputMap)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientAccountID")
	assert.Nil(outputSchemas, "accounts should be nil")
}

// TestPAPGetAllSchemasWithNotExistingSchema tests the get all schemas with not existing schema.
func TestPAPGetAllSchemasWithNotExistingSchema(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()

	accountsSQLSelect := "SELECT .+ FROM \"schemas\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnError(errors.New("something bad has happened"))

	inputMap := map[string]interface{}{
		azmodels.FieldSchemaSchemaID: "54ab73ef-92c9-4b59-9798-8f9dd47fb42e",
	}
	outputSchemas, err := storage.GetAllSchemas(account.AccountID, inputMap)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrClientAccountID")
	assert.Nil(outputSchemas, "accounts should be nil")
}

// TestPAPGetAllSchemasWithSuccess tests the get all schemas with success.
func TestPAPGetAllSchemasWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	schemas, _, sqlSchemas := registerSchemaForGetAllMocking()

	accountsSQLSelect := "SELECT .+ FROM \"schemas\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlSchemas)

	inputMap := map[string]interface{}{
		azmodels.FieldSchemaSchemaID: "54ab73ef-92c9-4b59-9798-8f9dd47fb42e",
	}
	outputSchemas, err := storage.GetAllSchemas(account.AccountID, inputMap)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputSchemas, "account should be not nil")
	assert.Equal(len(schemas), len(outputSchemas), "accounts should be equal")
	for i, outputSchema := range outputSchemas {
		assert.Equal(schemas[i].SchemaID, outputSchema.SchemaID, "repository id is not correct")
	}
	assert.Nil(err, "error should be nil")
}
