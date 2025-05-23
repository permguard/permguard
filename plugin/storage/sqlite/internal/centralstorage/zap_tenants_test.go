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

// TestCreateTenantWithErrors tests the CreateTenant function with errors.
func TestCreateTenantWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil tenant
		storage, _, _, _, _, _, _ := createSQLiteZAPCentralStorageWithMocks()
		tenants, err := storage.CreateTenant(nil)
		assert.Nil(tenants, "tenants should be nil")
		assert.NotNil(err, "error should not be nil")
	}

	tests := map[string]struct {
		Error1 error
	}{
		"CONNECT-ERROR":  {Error1: errors.New("CONNECT-ERROR")},
		"BEGIN-ERROR":    {Error1: errors.New("BEGIN-ERROR")},
		"ROLLBACK-ERROR": {Error1: errors.New("ROLLBACK-ERROR")},
		"COMMIT-ERROR":   {Error1: errors.New("COMMIT-ERROR")},
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
			mockSQLRepo.On("UpsertTenant", mock.Anything, true, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertTenant", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inTenant := &zap.Tenant{}
		outTenants, err := storage.CreateTenant(inTenant)
		assert.Nil(outTenants, "tenants should be nil")
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			errs := multi.Unwrap()
			isErr := test.Error1.Error() == errs[0].Error()
			assert.True(isErr, "error should be equal")
		}
	}
}

// TestCreateTenantWithSuccess tests the CreateTenant function with success.
func TestCreateTenantWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()

	dbOutTenant := &repos.Tenant{
		ZoneID:    232956849236,
		TenantID:  repos.GenerateUUID(),
		Name:      "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertTenant", mock.Anything, true, mock.Anything).Return(dbOutTenant, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inTenant := &zap.Tenant{}
	outTenants, err := storage.CreateTenant(inTenant)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outTenants, "tenants should not be nil")
	assert.Equal(dbOutTenant.TenantID, outTenants.TenantID, "tenant id should be equal")
	assert.Equal(dbOutTenant.Name, outTenants.Name, "tenant name should be equal")
	assert.Equal(dbOutTenant.CreatedAt, outTenants.CreatedAt, "created at should be equal")
	assert.Equal(dbOutTenant.UpdatedAt, outTenants.UpdatedAt, "updated at should be equal")
}

// TestUpdateTenantWithErrors tests the UpdateTenant function with errors.
func TestUpdateTenantWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil tenant
		storage, _, _, _, _, _, _ := createSQLiteZAPCentralStorageWithMocks()
		tenants, err := storage.UpdateTenant(nil)
		assert.Nil(tenants, "tenants should be nil")
		assert.NotNil(err, "error should not be nil")
	}

	tests := map[string]struct {
		Error1 error
	}{
		"CONNECT-ERROR":  {Error1: errors.New("CONNECT-ERROR")},
		"BEGIN-ERROR":    {Error1: errors.New("BEGIN-ERROR")},
		"ROLLBACK-ERROR": {Error1: errors.New("ROLLBACK-ERROR")},
		"COMMIT-ERROR":   {Error1: errors.New("COMMIT-ERROR")},
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
			mockSQLRepo.On("UpsertTenant", mock.Anything, false, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertTenant", mock.Anything, false, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inTenant := &zap.Tenant{}
		outTenants, err := storage.UpdateTenant(inTenant)
		assert.Nil(outTenants, "tenants should be nil")
		assert.Error(err)
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			errs := multi.Unwrap()
			isErr := test.Error1.Error() == errs[0].Error()
			assert.True(isErr, "error should be equal")
		}
	}
}

// TestUpdateTenantWithSuccess tests the UpdateTenant function with success.
func TestUpdateTenantWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()

	dbOutTenant := &repos.Tenant{
		ZoneID:    232956849236,
		TenantID:  repos.GenerateUUID(),
		Name:      "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertTenant", mock.Anything, false, mock.Anything).Return(dbOutTenant, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inTenant := &zap.Tenant{}
	outTenants, err := storage.UpdateTenant(inTenant)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outTenants, "tenants should not be nil")
	assert.Equal(dbOutTenant.TenantID, outTenants.TenantID, "tenant id should be equal")
	assert.Equal(dbOutTenant.Name, outTenants.Name, "tenant name should be equal")
	assert.Equal(dbOutTenant.CreatedAt, outTenants.CreatedAt, "created at should be equal")
	assert.Equal(dbOutTenant.UpdatedAt, outTenants.UpdatedAt, "updated at should be equal")
}

// TestDeleteTenantWithErrors tests the DeleteTenant function with errors.
func TestDeleteTenantWithErrors(t *testing.T) {
	assert := assert.New(t)

	tests := map[string]struct {
		Error1 error
	}{
		"CONNECT-ERROR":  {Error1: errors.New("CONNECT-ERROR")},
		"BEGIN-ERROR":    {Error1: errors.New("BEGIN-ERROR")},
		"ROLLBACK-ERROR": {Error1: errors.New("ROLLBACK-ERROR")},
		"COMMIT-ERROR":   {Error1: errors.New("COMMIT-ERROR")},
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
			mockSQLRepo.On("DeleteTenant", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteTenant", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inTenantID := repos.GenerateUUID()
		outTenants, err := storage.DeleteTenant(repos.GenerateZoneID(), inTenantID)
		assert.Nil(outTenants, "tenants should be nil")
		assert.Error(err)
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			errs := multi.Unwrap()
			isErr := test.Error1.Error() == errs[0].Error()
			assert.True(isErr, "error should be equal")
		}
	}
}

// TestDeleteTenantWithSuccess tests the DeleteTenant function with success.
func TestDeleteTenantWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()

	dbOutTenant := &repos.Tenant{
		ZoneID:    232956849236,
		TenantID:  repos.GenerateUUID(),
		Name:      "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("DeleteTenant", mock.Anything, mock.Anything, mock.Anything).Return(dbOutTenant, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inTenantID := repos.GenerateUUID()
	outTenants, err := storage.DeleteTenant(repos.GenerateZoneID(), inTenantID)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outTenants, "tenants should not be nil")
	assert.Equal(dbOutTenant.TenantID, outTenants.TenantID, "tenant id should be equal")
	assert.Equal(dbOutTenant.Name, outTenants.Name, "tenant name should be equal")
	assert.Equal(dbOutTenant.CreatedAt, outTenants.CreatedAt, "created at should be equal")
	assert.Equal(dbOutTenant.UpdatedAt, outTenants.UpdatedAt, "updated at should be equal")
}

// TestFetchTenantWithErrors tests the FetchTenant function with errors.
func TestFetchTenantWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, _, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New("operation error"))
		outTenants, err := storage.FetchTenants(1, 100, 232956849236, nil)
		assert.Nil(outTenants, "tenants should be nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outTenants, err := storage.FetchTenants(0, 100, 232956849236, nil)
		assert.Nil(outTenants, "tenants should be nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with invalid page size
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outTenants, err := storage.FetchTenants(1, 0, 232956849236, nil)
		assert.Nil(outTenants, "tenants should be nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with invalid tenant id
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outTenants, err := storage.FetchTenants(1, 100, 232956849236, map[string]any{zap.FieldTenantTenantID: 232956849236})
		assert.Nil(outTenants, "tenants should be nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with invalid tenant name
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outTenants, err := storage.FetchTenants(1, 100, 232956849236, map[string]any{zap.FieldTenantName: 2})
		assert.Nil(outTenants, "tenants should be nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with server error
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		mockSQLRepo.On("FetchTenants", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("operation error"))
		outTenants, err := storage.FetchTenants(1, 100, 232956849236, nil)
		assert.Nil(outTenants, "tenants should be nil")
		assert.NotNil(err, "error should not be nil")
	}
}

// TestFetchTenantWithSuccess tests the FetchTenant function with success.
func TestFetchTenantWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()

	dbOutTenants := []repos.Tenant{
		{
			ZoneID:    232956849236,
			TenantID:  repos.GenerateUUID(),
			Name:      "rent-a-car1",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ZoneID:    232956849236,
			TenantID:  repos.GenerateUUID(),
			Name:      "rent-a-car2",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLRepo.On("FetchTenants", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbOutTenants, nil)

	outTenants, err := storage.FetchTenants(1, 100, 232956849236, map[string]any{zap.FieldTenantTenantID: repos.GenerateUUID(), zap.FieldTenantName: "rent-a-car2"})
	assert.Nil(err, "error should be nil")
	assert.NotNil(outTenants, "tenants should not be nil")
	assert.Equal(len(outTenants), len(dbOutTenants), "tenants and dbTenants should have the same length")
	for i, outTenant := range outTenants {
		assert.Equal(dbOutTenants[i].TenantID, outTenant.TenantID, "tenant id should be equal")
		assert.Equal(dbOutTenants[i].Name, outTenant.Name, "tenant name should be equal")
		assert.Equal(dbOutTenants[i].CreatedAt, outTenant.CreatedAt, "created at should be equal")
		assert.Equal(dbOutTenants[i].UpdatedAt, outTenant.UpdatedAt, "updated at should be equal")
	}
}
