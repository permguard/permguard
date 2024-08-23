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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// TestCreateRepositoryWithErrors tests the CreateRepository function with errors.
func TestCreateRepositoryWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil repository
		storage, _, _, _, _, _, _ := createSQLitePAPCentralStorageWithMocks()
		repositories, err := storage.CreateRepository(nil)
		assert.Nil(repositories, "repositories should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	tests := map[string]struct {
		IsCustomError bool
		Error1        error
	}{
		"CONNECT-ERROR":  {IsCustomError: true, Error1: azerrors.ErrStorageGeneric},
		"BEGIN-ERROR":    {IsCustomError: true, Error1: azerrors.ErrStorageGeneric},
		"ROLLBACK-ERROR": {IsCustomError: false, Error1: errors.New("ROLLBACK-ERROR")},
		"COMMIT-ERROR":   {IsCustomError: true, Error1: azerrors.ErrStorageGeneric},
	}
	for testcase, test := range tests {
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLitePAPCentralStorageWithMocks()
		switch testcase {
		case "CONNECT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New(testcase))
		case "BEGIN-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin().WillReturnError(errors.New(testcase))
		case "ROLLBACK-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertRepository", mock.Anything, true, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertRepository", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inRepository := &azmodels.Repository{}
		outRepositories, err := storage.CreateRepository(inRepository)
		assert.Nil(outRepositories, "repositories should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestCreateRepositoryWithSuccess tests the CreateRepository function with success.
func TestCreateRepositoryWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLitePAPCentralStorageWithMocks()

	dbOutRepository := &azirepos.Repository{
		AccountID:    232956849236,
		RepositoryID: azirepos.GenerateUUID(),
		Name:         "rent-a-car1",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertRepository", mock.Anything, true, mock.Anything).Return(dbOutRepository, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inRepository := &azmodels.Repository{}
	outRepositories, err := storage.CreateRepository(inRepository)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outRepositories, "repositories should not be nil")
	assert.Equal(dbOutRepository.RepositoryID, outRepositories.RepositoryID, "repository id should be equal")
	assert.Equal(dbOutRepository.Name, outRepositories.Name, "repository name should be equal")
	assert.Equal(dbOutRepository.CreatedAt, outRepositories.CreatedAt, "created at should be equal")
	assert.Equal(dbOutRepository.UpdatedAt, outRepositories.UpdatedAt, "updated at should be equal")
}

// TestUpdateRepositoryWithErrors tests the UpdateRepository function with errors.
func TestUpdateRepositoryWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil repository
		storage, _, _, _, _, _, _ := createSQLitePAPCentralStorageWithMocks()
		repositories, err := storage.UpdateRepository(nil)
		assert.Nil(repositories, "repositories should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	tests := map[string]struct {
		IsCustomError bool
		Error1        error
	}{
		"CONNECT-ERROR":  {IsCustomError: true, Error1: azerrors.ErrStorageGeneric},
		"BEGIN-ERROR":    {IsCustomError: true, Error1: azerrors.ErrStorageGeneric},
		"ROLLBACK-ERROR": {IsCustomError: false, Error1: errors.New("ROLLBACK-ERROR")},
		"COMMIT-ERROR":   {IsCustomError: true, Error1: azerrors.ErrStorageGeneric},
	}
	for testcase, test := range tests {
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLitePAPCentralStorageWithMocks()
		switch testcase {
		case "CONNECT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New(testcase))
		case "BEGIN-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin().WillReturnError(errors.New(testcase))
		case "ROLLBACK-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertRepository", mock.Anything, false, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertRepository", mock.Anything, false, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inRepository := &azmodels.Repository{}
		outRepositories, err := storage.UpdateRepository(inRepository)
		assert.Nil(outRepositories, "repositories should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestUpdateRepositoryWithSuccess tests the UpdateRepository function with success.
func TestUpdateRepositoryWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLitePAPCentralStorageWithMocks()

	dbOutRepository := &azirepos.Repository{
		AccountID:    232956849236,
		RepositoryID: azirepos.GenerateUUID(),
		Name:         "rent-a-car1",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertRepository", mock.Anything, false, mock.Anything).Return(dbOutRepository, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inRepository := &azmodels.Repository{}
	outRepositories, err := storage.UpdateRepository(inRepository)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outRepositories, "repositories should not be nil")
	assert.Equal(dbOutRepository.RepositoryID, outRepositories.RepositoryID, "repository id should be equal")
	assert.Equal(dbOutRepository.Name, outRepositories.Name, "repository name should be equal")
	assert.Equal(dbOutRepository.CreatedAt, outRepositories.CreatedAt, "created at should be equal")
	assert.Equal(dbOutRepository.UpdatedAt, outRepositories.UpdatedAt, "updated at should be equal")
}

// TestDeleteRepositoryWithErrors tests the DeleteRepository function with errors.
func TestDeleteRepositoryWithErrors(t *testing.T) {
	assert := assert.New(t)

	tests := map[string]struct {
		IsCustomError bool
		Error1        error
	}{
		"CONNECT-ERROR":  {IsCustomError: true, Error1: azerrors.ErrStorageGeneric},
		"BEGIN-ERROR":    {IsCustomError: true, Error1: azerrors.ErrStorageGeneric},
		"ROLLBACK-ERROR": {IsCustomError: false, Error1: errors.New("ROLLBACK-ERROR")},
		"COMMIT-ERROR":   {IsCustomError: true, Error1: azerrors.ErrStorageGeneric},
	}
	for testcase, test := range tests {
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLitePAPCentralStorageWithMocks()
		switch testcase {
		case "CONNECT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New(testcase))
		case "BEGIN-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin().WillReturnError(errors.New(testcase))
		case "ROLLBACK-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteRepository", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteRepository", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inRepositoryID := azirepos.GenerateUUID()
		outRepositories, err := storage.DeleteRepository(azirepos.GenerateAccountID(), inRepositoryID)
		assert.Nil(outRepositories, "repositories should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestDeleteRepositoryWithSuccess tests the DeleteRepository function with success.
func TestDeleteRepositoryWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLitePAPCentralStorageWithMocks()

	dbOutRepository := &azirepos.Repository{
		AccountID:    232956849236,
		RepositoryID: azirepos.GenerateUUID(),
		Name:         "rent-a-car1",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("DeleteRepository", mock.Anything, mock.Anything, mock.Anything).Return(dbOutRepository, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inRepositoryID := azirepos.GenerateUUID()
	outRepositories, err := storage.DeleteRepository(azirepos.GenerateAccountID(), inRepositoryID)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outRepositories, "repositories should not be nil")
	assert.Equal(dbOutRepository.RepositoryID, outRepositories.RepositoryID, "repository id should be equal")
	assert.Equal(dbOutRepository.Name, outRepositories.Name, "repository name should be equal")
	assert.Equal(dbOutRepository.CreatedAt, outRepositories.CreatedAt, "created at should be equal")
	assert.Equal(dbOutRepository.UpdatedAt, outRepositories.UpdatedAt, "updated at should be equal")
}

// TestFetchRepositoryWithErrors tests the FetchRepository function with errors.
func TestFetchRepositoryWithErrors(t *testing.T) {
	assert := assert.New(t)

	{	// Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, _, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, azerrors.ErrServerGeneric)
		outRepositories, err := storage.FetchRepositories(1, 100, 232956849236, nil)
		assert.Nil(outRepositories, "repositories should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrServerGeneric, err), "error should be errservergeneric")
	}

	{	// Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outRepositories, err := storage.FetchRepositories(0, 100, 232956849236, nil)
		assert.Nil(outRepositories, "repositories should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{	// Test with invalid page size
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outRepositories, err := storage.FetchRepositories(1, 0, 232956849236, nil)
		assert.Nil(outRepositories, "repositories should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{	// Test with invalid repository id
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outRepositories, err := storage.FetchRepositories(1, 100, 232956849236, map[string]interface{}{azmodels.FieldRepositoryRepositoryID: 232956849236})
		assert.Nil(outRepositories, "repositories should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{	// Test with invalid repository name
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outRepositories, err := storage.FetchRepositories(1, 100, 232956849236, map[string]interface{}{azmodels.FieldRepositoryName: 2 })
		assert.Nil(outRepositories, "repositories should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{	// Test with server error
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		mockSQLRepo.On("FetchRepositories",mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, azerrors.ErrServerGeneric)
		outRepositories, err := storage.FetchRepositories(1, 100, 232956849236, nil)
		assert.Nil(outRepositories, "repositories should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrServerGeneric, err), "error should be errservergeneric")
	}
}

// TestFetchRepositoryWithSuccess tests the FetchRepository function with success.
func TestFetchRepositoryWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()

	dbOutRepositories := []azirepos.Repository{
		{
			AccountID:    232956849236,
			RepositoryID: azirepos.GenerateUUID(),
			Name:         "rent-a-car1",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
		{
			AccountID:    232956849236,
			RepositoryID: azirepos.GenerateUUID(),
			Name:         "rent-a-car2",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLRepo.On("FetchRepositories", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbOutRepositories, nil)

	outRepositories, err := storage.FetchRepositories(1, 100, 232956849236, map[string]interface{}{azmodels.FieldRepositoryRepositoryID: azirepos.GenerateUUID(), azmodels.FieldRepositoryName: "rent-a-car2"})
	assert.Nil(err, "error should be nil")
	assert.NotNil(outRepositories, "repositories should not be nil")
	assert.Equal(len(outRepositories), len(dbOutRepositories), "repositories and dbRepositories should have the same length")
	for i, outRepository := range outRepositories {
		assert.Equal(dbOutRepositories[i].RepositoryID, outRepository.RepositoryID, "repository id should be equal")
		assert.Equal(dbOutRepositories[i].Name, outRepository.Name, "repository name should be equal")
		assert.Equal(dbOutRepositories[i].CreatedAt, outRepository.CreatedAt, "created at should be equal")
		assert.Equal(dbOutRepositories[i].UpdatedAt, outRepository.UpdatedAt, "updated at should be equal")
	}
}
