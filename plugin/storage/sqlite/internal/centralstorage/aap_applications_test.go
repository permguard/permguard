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
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/facade"
)

// TestCreateApplicationWithErrors tests the CreateApplication function with errors.
func TestCreateApplicationWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil application
		storage, _, _, _, _, _, _ := createSQLiteAAPCentralStorageWithMocks()
		applications, err := storage.CreateApplication(nil)
		assert.Nil(applications, "applications should be nil")
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
			mockSQLRepo.On("UpsertApplication", mock.Anything, true, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			application := &azirepos.Application{
				ApplicationID: 232956849236,
				Name:          "rent-a-car1",
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}
			mockSQLRepo.On("UpsertApplication", mock.Anything, true, mock.Anything).Return(application, nil)
			mockSQLRepo.On("UpsertTenant", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLRepo.On("UpsertIdentitySource", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLRepo.On("UpsertLedger", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inApplication := &azmodels.Application{}
		outApplications, err := storage.CreateApplication(inApplication)
		assert.Nil(outApplications, "applications should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestCreateApplicationWithSuccess tests the CreateApplication function with success.
func TestCreateApplicationWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()

	dbOutApplication := &azirepos.Application{
		ApplicationID: 232956849236,
		Name:          "rent-a-car1",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertApplication", mock.Anything, true, mock.Anything).Return(dbOutApplication, nil)
	mockSQLRepo.On("UpsertTenant", mock.Anything, true, mock.Anything).Return(nil, nil)
	mockSQLRepo.On("UpsertIdentitySource", mock.Anything, true, mock.Anything).Return(nil, nil)
	mockSQLRepo.On("UpsertLedger", mock.Anything, true, mock.Anything).Return(nil, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inApplication := &azmodels.Application{}
	outApplications, err := storage.CreateApplication(inApplication)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outApplications, "applications should not be nil")
	assert.Equal(dbOutApplication.ApplicationID, outApplications.ApplicationID, "application id should be equal")
	assert.Equal(dbOutApplication.Name, outApplications.Name, "application name should be equal")
	assert.Equal(dbOutApplication.CreatedAt, outApplications.CreatedAt, "created at should be equal")
	assert.Equal(dbOutApplication.UpdatedAt, outApplications.UpdatedAt, "updated at should be equal")
}

// TestUpdateApplicationWithErrors tests the UpdateApplication function with errors.
func TestUpdateApplicationWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil application
		storage, _, _, _, _, _, _ := createSQLiteAAPCentralStorageWithMocks()
		applications, err := storage.UpdateApplication(nil)
		assert.Nil(applications, "applications should be nil")
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
			mockSQLRepo.On("UpsertApplication", mock.Anything, false, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			application := &azirepos.Application{
				ApplicationID: 232956849236,
				Name:          "rent-a-car1",
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}
			mockSQLRepo.On("UpsertApplication", mock.Anything, false, mock.Anything).Return(application, nil)
			mockSQLRepo.On("UpsertTenant", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLRepo.On("UpsertIdentitySource", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLRepo.On("UpsertLedger", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inApplication := &azmodels.Application{}
		outApplications, err := storage.UpdateApplication(inApplication)
		assert.Nil(outApplications, "applications should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestUpdateApplicationWithSuccess tests the UpdateApplication function with success.
func TestUpdateApplicationWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()

	dbOutApplication := &azirepos.Application{
		ApplicationID: 232956849236,
		Name:          "rent-a-car1",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertApplication", mock.Anything, false, mock.Anything).Return(dbOutApplication, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inApplication := &azmodels.Application{}
	outApplications, err := storage.UpdateApplication(inApplication)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outApplications, "applications should not be nil")
	assert.Equal(dbOutApplication.ApplicationID, outApplications.ApplicationID, "application id should be equal")
	assert.Equal(dbOutApplication.Name, outApplications.Name, "application name should be equal")
	assert.Equal(dbOutApplication.CreatedAt, outApplications.CreatedAt, "created at should be equal")
	assert.Equal(dbOutApplication.UpdatedAt, outApplications.UpdatedAt, "updated at should be equal")
}

// TestDeleteApplicationWithErrors tests the DeleteApplication function with errors.
func TestDeleteApplicationWithErrors(t *testing.T) {
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
			mockSQLRepo.On("DeleteApplication", mock.Anything, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteApplication", mock.Anything, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inApplicationID := int64(232956849236)
		outApplications, err := storage.DeleteApplication(inApplicationID)
		assert.Nil(outApplications, "applications should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestDeleteApplicationWithSuccess tests the DeleteApplication function with success.
func TestDeleteApplicationWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()

	dbOutApplication := &azirepos.Application{
		ApplicationID: 232956849236,
		Name:          "rent-a-car1",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("DeleteApplication", mock.Anything, mock.Anything).Return(dbOutApplication, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inApplicationID := int64(232956849236)
	outApplications, err := storage.DeleteApplication(inApplicationID)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outApplications, "applications should not be nil")
	assert.Equal(dbOutApplication.ApplicationID, outApplications.ApplicationID, "application id should be equal")
	assert.Equal(dbOutApplication.Name, outApplications.Name, "application name should be equal")
	assert.Equal(dbOutApplication.CreatedAt, outApplications.CreatedAt, "created at should be equal")
	assert.Equal(dbOutApplication.UpdatedAt, outApplications.UpdatedAt, "updated at should be equal")
}

// TestFetchApplicationWithErrors tests the FetchApplication function with errors.
func TestFetchApplicationWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, _, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, azerrors.ErrServerGeneric)
		outApplications, err := storage.FetchApplications(1, 100, nil)
		assert.Nil(outApplications, "applications should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrServerGeneric, err), "error should be errservergeneric")
	}

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outApplications, err := storage.FetchApplications(0, 100, nil)
		assert.Nil(outApplications, "applications should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid page size
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outApplications, err := storage.FetchApplications(1, 0, nil)
		assert.Nil(outApplications, "applications should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid application id
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outApplications, err := storage.FetchApplications(1, 100, map[string]any{azmodels.FieldApplicationApplicationID: "not valid"})
		assert.Nil(outApplications, "applications should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid application name
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outApplications, err := storage.FetchApplications(1, 100, map[string]any{azmodels.FieldApplicationName: 2})
		assert.Nil(outApplications, "applications should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid application name
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		mockSQLRepo.On("FetchApplications", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, azerrors.ErrServerGeneric)
		outApplications, err := storage.FetchApplications(1, 100, nil)
		assert.Nil(outApplications, "applications should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrServerGeneric, err), "error should be errservergeneric")
	}
}

// TestFetchApplicationWithSuccess tests the DeleteApplication function with success.
func TestFetchApplicationWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()

	dbOutApplications := []azirepos.Application{
		{
			ApplicationID: 232956849236,
			Name:          "rent-a-car1",
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
		{
			ApplicationID: 506074038324,
			Name:          "rent-a-car2",
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLRepo.On("FetchApplications", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbOutApplications, nil)

	outApplications, err := storage.FetchApplications(1, 100, map[string]any{azmodels.FieldApplicationApplicationID: int64(506074038324), azmodels.FieldApplicationName: "rent-a-car2"})
	assert.Nil(err, "error should be nil")
	assert.NotNil(outApplications, "applications should not be nil")
	assert.Equal(len(dbOutApplications), len(outApplications), "applications  and dbApplications should have the same length")
	for i, outApplication := range outApplications {
		assert.Equal(dbOutApplications[i].ApplicationID, outApplication.ApplicationID, "application id should be equal")
		assert.Equal(dbOutApplications[i].Name, outApplication.Name, "application name should be equal")
		assert.Equal(dbOutApplications[i].CreatedAt, outApplication.CreatedAt, "created at should be equal")
		assert.Equal(dbOutApplications[i].UpdatedAt, outApplication.UpdatedAt, "updated at should be equal")
	}
}
