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

	"github.com/permguard/permguard/pkg/transport/models/zap"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// TestCreateIdentityWithErrors tests the CreateIdentity function with errors.
func TestCreateIdentityWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil identity
		storage, _, _, _, _, _, _ := createSQLiteZAPCentralStorageWithMocks()
		identities, err := storage.CreateIdentity(nil)
		assert.Nil(identities, "identities should be nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientparameter")
	}

	tests := map[string]struct {
		IsCustomError bool
		Error1        error
	}{
		"CONNECT-ERROR":  {IsCustomError: true, Error1: errors.New("operation error")},
		"BEGIN-ERROR":    {IsCustomError: true, Error1: errors.New("operation error")},
		"ROLLBACK-ERROR": {IsCustomError: false, Error1: errors.New("ROLLBACK-ERROR")},
		"COMMIT-ERROR":   {IsCustomError: true, Error1: errors.New("operation error")},
	}
	for testcase, test := range tests {
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()
		switch testcase {
		case "CONNECT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New(testcase))
		case "BEGIN-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin().WillReturnError(errors.New(testcase))
		case "ROLLBACK-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertIdentity", mock.Anything, true, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertIdentity", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inIdentity := &zap.Identity{
			Kind: "user",
		}
		outIdentities, err := storage.CreateIdentity(inIdentity)
		assert.Nil(outIdentities, "identities should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(errors.Is(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestCreateIdentityWithSuccess tests the CreateIdentity function with success.
func TestCreateIdentityWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()

	dbOutIdentity := &repos.Identity{
		IdentityID:       repos.GenerateUUID(),
		ZoneID:           581616507495,
		IdentitySourceID: repos.GenerateUUID(),
		Kind:             1,
		Name:             "nicola.gallo",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertIdentity", mock.Anything, true, mock.Anything).Return(dbOutIdentity, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inIdentity := &zap.Identity{
		Kind: "user",
	}
	outIdentities, err := storage.CreateIdentity(inIdentity)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outIdentities, "identities should not be nil")
	assert.Equal(dbOutIdentity.IdentityID, outIdentities.IdentityID, "identity id should be equal")
	assert.Equal(dbOutIdentity.Name, outIdentities.Name, "identity name should be equal")
	assert.Equal(dbOutIdentity.CreatedAt, outIdentities.CreatedAt, "created at should be equal")
	assert.Equal(dbOutIdentity.UpdatedAt, outIdentities.UpdatedAt, "updated at should be equal")
}

// TestUpdateIdentityWithErrors tests the UpdateIdentity function with errors.
func TestUpdateIdentityWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil identity
		storage, _, _, _, _, _, _ := createSQLiteZAPCentralStorageWithMocks()
		identities, err := storage.UpdateIdentity(nil)
		assert.Nil(identities, "identities should be nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientparameter")
	}

	tests := map[string]struct {
		IsCustomError bool
		Error1        error
	}{
		"CONNECT-ERROR":  {IsCustomError: true, Error1: errors.New("operation error")},
		"BEGIN-ERROR":    {IsCustomError: true, Error1: errors.New("operation error")},
		"ROLLBACK-ERROR": {IsCustomError: false, Error1: errors.New("ROLLBACK-ERROR")},
		"COMMIT-ERROR":   {IsCustomError: true, Error1: errors.New("operation error")},
	}
	for testcase, test := range tests {
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()
		switch testcase {
		case "CONNECT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New(testcase))
		case "BEGIN-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin().WillReturnError(errors.New(testcase))
		case "ROLLBACK-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertIdentity", mock.Anything, false, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertIdentity", mock.Anything, false, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inIdentity := &zap.Identity{
			Kind: "user",
		}
		outIdentities, err := storage.UpdateIdentity(inIdentity)
		assert.Nil(outIdentities, "identities should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(errors.Is(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestUpdateIdentityWithSuccess tests the UpdateIdentity function with success.
func TestUpdateIdentityWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()

	dbOutIdentity := &repos.Identity{
		IdentityID:       repos.GenerateUUID(),
		ZoneID:           581616507495,
		IdentitySourceID: repos.GenerateUUID(),
		Kind:             1,
		Name:             "nicola.gallo",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertIdentity", mock.Anything, false, mock.Anything).Return(dbOutIdentity, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inIdentity := &zap.Identity{
		Kind: "user",
	}
	outIdentities, err := storage.UpdateIdentity(inIdentity)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outIdentities, "identities should not be nil")
	assert.Equal(dbOutIdentity.IdentityID, outIdentities.IdentityID, "identity id should be equal")
	assert.Equal(dbOutIdentity.Name, outIdentities.Name, "identity name should be equal")
	assert.Equal(dbOutIdentity.CreatedAt, outIdentities.CreatedAt, "created at should be equal")
	assert.Equal(dbOutIdentity.UpdatedAt, outIdentities.UpdatedAt, "updated at should be equal")
}

// TestDeleteIdentityWithErrors tests the DeleteIdentity function with errors.
func TestDeleteIdentityWithErrors(t *testing.T) {
	assert := assert.New(t)

	tests := map[string]struct {
		IsCustomError bool
		Error1        error
	}{
		"CONNECT-ERROR":  {IsCustomError: true, Error1: errors.New("operation error")},
		"BEGIN-ERROR":    {IsCustomError: true, Error1: errors.New("operation error")},
		"ROLLBACK-ERROR": {IsCustomError: false, Error1: errors.New("ROLLBACK-ERROR")},
		"COMMIT-ERROR":   {IsCustomError: true, Error1: errors.New("operation error")},
	}
	for testcase, test := range tests {
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()
		switch testcase {
		case "CONNECT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New(testcase))
		case "BEGIN-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin().WillReturnError(errors.New(testcase))
		case "ROLLBACK-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteIdentity", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteIdentity", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inIdentityID := repos.GenerateUUID()
		outIdentities, err := storage.DeleteIdentity(repos.GenerateZoneID(), inIdentityID)
		assert.Nil(outIdentities, "identities should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(errors.Is(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestDeleteIdentityWithSuccess tests the DeleteIdentity function with success.
func TestDeleteIdentityWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()

	dbOutIdentity := &repos.Identity{
		IdentityID:       repos.GenerateUUID(),
		ZoneID:           581616507495,
		IdentitySourceID: repos.GenerateUUID(),
		Kind:             1,
		Name:             "nicola.gallo",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("DeleteIdentity", mock.Anything, mock.Anything, mock.Anything).Return(dbOutIdentity, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inIdentityID := repos.GenerateUUID()
	outIdentities, err := storage.DeleteIdentity(repos.GenerateZoneID(), inIdentityID)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outIdentities, "identities should not be nil")
	assert.Equal(dbOutIdentity.IdentityID, outIdentities.IdentityID, "identity id should be equal")
	assert.Equal(dbOutIdentity.Name, outIdentities.Name, "identity name should be equal")
	assert.Equal(dbOutIdentity.CreatedAt, outIdentities.CreatedAt, "created at should be equal")
	assert.Equal(dbOutIdentity.UpdatedAt, outIdentities.UpdatedAt, "updated at should be equal")
}

// TestFetchIdentityWithErrors tests the FetchIdentity function with errors.
func TestFetchIdentityWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, _, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New("operation error"))
		outIdentities, err := storage.FetchIdentities(1, 100, 232956849236, nil)
		assert.Nil(outIdentities, "identities should be nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errservergeneric")
	}

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outIdentities, err := storage.FetchIdentities(0, 100, 232956849236, nil)
		assert.Nil(outIdentities, "identities should be nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientpagination")
	}

	{ // Test with invalid page size
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outIdentities, err := storage.FetchIdentities(1, 0, 232956849236, nil)
		assert.Nil(outIdentities, "identities should be nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientpagination")
	}

	{ // Test with invalid identity id
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outIdentities, err := storage.FetchIdentities(1, 100, 232956849236, map[string]any{zap.FieldIdentityIdentityID: 232956849236})
		assert.Nil(outIdentities, "identities should be nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientparameter")
	}

	{ // Test with invalid identity name
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outIdentities, err := storage.FetchIdentities(1, 100, 232956849236, map[string]any{zap.FieldIdentityName: 2})
		assert.Nil(outIdentities, "identities should be nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientparameter")
	}

	{ // Test with server error
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		mockSQLRepo.On("FetchIdentities", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("operation error"))
		outIdentities, err := storage.FetchIdentities(1, 100, 232956849236, nil)
		assert.Nil(outIdentities, "identities should be nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errservergeneric")
	}
}

// TestFetchIdentityWithSuccess tests the FetchIdentity function with success.
func TestFetchIdentityWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()

	dbOutIdentities := []repos.Identity{
		{
			IdentityID:       repos.GenerateUUID(),
			ZoneID:           232956849236,
			IdentitySourceID: repos.GenerateUUID(),
			Kind:             1,
			Name:             "nicola.gallo",
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
		{
			IdentityID:       repos.GenerateUUID(),
			ZoneID:           232956849236,
			IdentitySourceID: repos.GenerateUUID(),
			Kind:             1,
			Name:             "francesco.gallo",
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLRepo.On("FetchIdentities", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbOutIdentities, nil)

	outIdentities, err := storage.FetchIdentities(1, 100, 232956849236, map[string]any{zap.FieldIdentityIdentityID: repos.GenerateUUID(), zap.FieldIdentityName: "rent-a-car2"})
	assert.Nil(err, "error should be nil")
	assert.NotNil(outIdentities, "identities should not be nil")
	assert.Equal(len(outIdentities), len(dbOutIdentities), "identities and dbIdentities should have the same length")
	for i, outIdentity := range outIdentities {
		assert.Equal(dbOutIdentities[i].IdentityID, outIdentity.IdentityID, "identity id should be equal")
		assert.Equal(dbOutIdentities[i].Name, outIdentity.Name, "identity name should be equal")
		assert.Equal(dbOutIdentities[i].CreatedAt, outIdentity.CreatedAt, "created at should be equal")
		assert.Equal(dbOutIdentities[i].UpdatedAt, outIdentity.UpdatedAt, "updated at should be equal")
	}
}
