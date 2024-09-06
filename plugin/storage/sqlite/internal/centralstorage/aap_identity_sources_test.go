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

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// TestCreateIdentitySourceWithErrors tests the CreateIdentitySource function with errors.
func TestCreateIdentitySourceWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil identity source
		storage, _, _, _, _, _, _ := createSQLiteAAPCentralStorageWithMocks()
		identitySources, err := storage.CreateIdentitySource(nil)
		assert.Nil(identitySources, "identity sources should be nil")
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
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()
		switch testcase {
		case "CONNECT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New(testcase))
		case "BEGIN-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin().WillReturnError(errors.New(testcase))
		case "ROLLBACK-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertIdentitySource", mock.Anything, true, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertIdentitySource", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inIdentitySource := &azmodels.IdentitySource{}
		outIdentitySources, err := storage.CreateIdentitySource(inIdentitySource)
		assert.Nil(outIdentitySources, "identity sources should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestCreateIdentitySourceWithSuccess tests the CreateIdentitySource function with success.
func TestCreateIdentitySourceWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()

	dbOutIdentitySource := &azirepos.IdentitySource{
		AccountID:        232956849236,
		IdentitySourceID: azirepos.GenerateUUID(),
		Name:             "rent-a-car1",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertIdentitySource", mock.Anything, true, mock.Anything).Return(dbOutIdentitySource, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inIdentitySource := &azmodels.IdentitySource{}
	outIdentitySources, err := storage.CreateIdentitySource(inIdentitySource)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outIdentitySources, "identity sources should not be nil")
	assert.Equal(dbOutIdentitySource.IdentitySourceID, outIdentitySources.IdentitySourceID, "identity source id should be equal")
	assert.Equal(dbOutIdentitySource.Name, outIdentitySources.Name, "identity source name should be equal")
	assert.Equal(dbOutIdentitySource.CreatedAt, outIdentitySources.CreatedAt, "created at should be equal")
	assert.Equal(dbOutIdentitySource.UpdatedAt, outIdentitySources.UpdatedAt, "updated at should be equal")
}

// TestUpdateIdentitySourceWithErrors tests the UpdateIdentitySource function with errors.
func TestUpdateIdentitySourceWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil identity source
		storage, _, _, _, _, _, _ := createSQLiteAAPCentralStorageWithMocks()
		identitySources, err := storage.UpdateIdentitySource(nil)
		assert.Nil(identitySources, "identity sources should be nil")
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
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()
		switch testcase {
		case "CONNECT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New(testcase))
		case "BEGIN-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin().WillReturnError(errors.New(testcase))
		case "ROLLBACK-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertIdentitySource", mock.Anything, false, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertIdentitySource", mock.Anything, false, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inIdentitySource := &azmodels.IdentitySource{}
		outIdentitySources, err := storage.UpdateIdentitySource(inIdentitySource)
		assert.Nil(outIdentitySources, "identity sources should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestUpdateIdentitySourceWithSuccess tests the UpdateIdentitySource function with success.
func TestUpdateIdentitySourceWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()

	dbOutIdentitySource := &azirepos.IdentitySource{
		AccountID:        232956849236,
		IdentitySourceID: azirepos.GenerateUUID(),
		Name:             "rent-a-car1",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertIdentitySource", mock.Anything, false, mock.Anything).Return(dbOutIdentitySource, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inIdentitySource := &azmodels.IdentitySource{}
	outIdentitySources, err := storage.UpdateIdentitySource(inIdentitySource)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outIdentitySources, "identity sources should not be nil")
	assert.Equal(dbOutIdentitySource.IdentitySourceID, outIdentitySources.IdentitySourceID, "identity source id should be equal")
	assert.Equal(dbOutIdentitySource.Name, outIdentitySources.Name, "identity source name should be equal")
	assert.Equal(dbOutIdentitySource.CreatedAt, outIdentitySources.CreatedAt, "created at should be equal")
	assert.Equal(dbOutIdentitySource.UpdatedAt, outIdentitySources.UpdatedAt, "updated at should be equal")
}

// TestDeleteIdentitySourceWithErrors tests the DeleteIdentitySource function with errors.
func TestDeleteIdentitySourceWithErrors(t *testing.T) {
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
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()
		switch testcase {
		case "CONNECT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New(testcase))
		case "BEGIN-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin().WillReturnError(errors.New(testcase))
		case "ROLLBACK-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteIdentitySource", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteIdentitySource", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inIdentitySourceID := azirepos.GenerateUUID()
		outIdentitySources, err := storage.DeleteIdentitySource(azirepos.GenerateAccountID(), inIdentitySourceID)
		assert.Nil(outIdentitySources, "identity sources should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestDeleteIdentitySourceWithSuccess tests the DeleteIdentitySource function with success.
func TestDeleteIdentitySourceWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()

	dbOutIdentitySource := &azirepos.IdentitySource{
		AccountID:        232956849236,
		IdentitySourceID: azirepos.GenerateUUID(),
		Name:             "rent-a-car1",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("DeleteIdentitySource", mock.Anything, mock.Anything, mock.Anything).Return(dbOutIdentitySource, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inIdentitySourceID := azirepos.GenerateUUID()
	outIdentitySources, err := storage.DeleteIdentitySource(azirepos.GenerateAccountID(), inIdentitySourceID)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outIdentitySources, "identity sources should not be nil")
	assert.Equal(dbOutIdentitySource.IdentitySourceID, outIdentitySources.IdentitySourceID, "identity source id should be equal")
	assert.Equal(dbOutIdentitySource.Name, outIdentitySources.Name, "identity source name should be equal")
	assert.Equal(dbOutIdentitySource.CreatedAt, outIdentitySources.CreatedAt, "created at should be equal")
	assert.Equal(dbOutIdentitySource.UpdatedAt, outIdentitySources.UpdatedAt, "updated at should be equal")
}

// TestFetchIdentitySourceWithErrors tests the FetchIdentitySource function with errors.
func TestFetchIdentitySourceWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, _, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, azerrors.ErrServerGeneric)
		outIdentitySources, err := storage.FetchIdentitySources(1, 100, 232956849236, nil)
		assert.Nil(outIdentitySources, "identity sources should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrServerGeneric, err), "error should be errservergeneric")
	}

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outIdentitySources, err := storage.FetchIdentitySources(0, 100, 232956849236, nil)
		assert.Nil(outIdentitySources, "identity sources should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid page size
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outIdentitySources, err := storage.FetchIdentitySources(1, 0, 232956849236, nil)
		assert.Nil(outIdentitySources, "identity sources should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid identity source id
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outIdentitySources, err := storage.FetchIdentitySources(1, 100, 232956849236, map[string]any{azmodels.FieldIdentitySourceIdentitySourceID: 232956849236})
		assert.Nil(outIdentitySources, "identity sources should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid identity source name
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outIdentitySources, err := storage.FetchIdentitySources(1, 100, 232956849236, map[string]any{azmodels.FieldIdentitySourceName: 2})
		assert.Nil(outIdentitySources, "identity sources should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with server error
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		mockSQLRepo.On("FetchIdentitySources", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, azerrors.ErrServerGeneric)
		outIdentitySources, err := storage.FetchIdentitySources(1, 100, 232956849236, nil)
		assert.Nil(outIdentitySources, "identity sources should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrServerGeneric, err), "error should be errservergeneric")
	}
}

// TestFetchIdentitySourceWithSuccess tests the FetchIdentitySource function with success.
func TestFetchIdentitySourceWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()

	dbOutIdentitySources := []azirepos.IdentitySource{
		{
			AccountID:        232956849236,
			IdentitySourceID: azirepos.GenerateUUID(),
			Name:             "rent-a-car1",
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
		{
			AccountID:        232956849236,
			IdentitySourceID: azirepos.GenerateUUID(),
			Name:             "rent-a-car2",
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLRepo.On("FetchIdentitySources", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbOutIdentitySources, nil)

	outIdentitySources, err := storage.FetchIdentitySources(1, 100, 232956849236, map[string]any{azmodels.FieldIdentitySourceIdentitySourceID: azirepos.GenerateUUID(), azmodels.FieldIdentitySourceName: "rent-a-car2"})
	assert.Nil(err, "error should be nil")
	assert.NotNil(outIdentitySources, "identity sources should not be nil")
	assert.Equal(len(outIdentitySources), len(dbOutIdentitySources), "identity sources and dbIdentitySources should have the same length")
	for i, outIdentitySource := range outIdentitySources {
		assert.Equal(dbOutIdentitySources[i].IdentitySourceID, outIdentitySource.IdentitySourceID, "identity source id should be equal")
		assert.Equal(dbOutIdentitySources[i].Name, outIdentitySource.Name, "identity source name should be equal")
		assert.Equal(dbOutIdentitySources[i].CreatedAt, outIdentitySource.CreatedAt, "created at should be equal")
		assert.Equal(dbOutIdentitySources[i].UpdatedAt, outIdentitySource.UpdatedAt, "updated at should be equal")
	}
}
