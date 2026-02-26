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
	"github.com/stretchr/testify/require"

	"github.com/permguard/permguard/pkg/transport/models/zap"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// TestCreateZoneWithErrors tests the CreateZone function with errors.
func TestCreateZoneWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil zone
		storage, _, _, _, _, _, _ := createSQLiteZAPCentralStorageWithMocks()
		zones, err := storage.CreateZone(nil)
		assert.Nil(zones, "zones should be nil")
		require.Error(t, err, "error should not be nil")
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
			mockSQLRepo.On("UpsertZone", mock.Anything, true, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			zone := &repos.Zone{
				ZoneID:    232956849236,
				Name:      "rent-a-car1",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			mockSQLRepo.On("UpsertZone", mock.Anything, true, mock.Anything).Return(zone, nil)
			mockSQLRepo.On("UpsertLedger", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inZone := &zap.Zone{}
		outZones, err := storage.CreateZone(inZone)
		assert.Nil(outZones, "zones should be nil")
		require.Error(t, err)
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			errs := multi.Unwrap()
			isErr := test.Error1.Error() == errs[0].Error()
			assert.True(isErr, "error should be equal")
		}
	}
}

// TestCreateZoneWithSuccess tests the CreateZone function with success.
func TestCreateZoneWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()

	dbOutZone := &repos.Zone{
		ZoneID:    232956849236,
		Name:      "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertZone", mock.Anything, true, mock.Anything).Return(dbOutZone, nil)
	mockSQLRepo.On("UpsertLedger", mock.Anything, true, mock.Anything).Return(nil, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inZone := &zap.Zone{}
	outZones, err := storage.CreateZone(inZone)
	require.NoError(t, err, "error should be nil")
	assert.NotNil(outZones, "zones should not be nil")
	assert.Equal(dbOutZone.ZoneID, outZones.ZoneID, "zone id should be equal")
	assert.Equal(dbOutZone.Name, outZones.Name, "zone name should be equal")
	assert.Equal(dbOutZone.CreatedAt, outZones.CreatedAt, "created at should be equal")
	assert.Equal(dbOutZone.UpdatedAt, outZones.UpdatedAt, "updated at should be equal")
}

// TestUpdateZoneWithErrors tests the UpdateZone function with errors.
func TestUpdateZoneWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil zone
		storage, _, _, _, _, _, _ := createSQLiteZAPCentralStorageWithMocks()
		zones, err := storage.UpdateZone(nil)
		assert.Nil(zones, "zones should be nil")
		require.Error(t, err, "error should not be nil")
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
			mockSQLRepo.On("UpsertZone", mock.Anything, false, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			zone := &repos.Zone{
				ZoneID:    232956849236,
				Name:      "rent-a-car1",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			mockSQLRepo.On("UpsertZone", mock.Anything, false, mock.Anything).Return(zone, nil)
			mockSQLRepo.On("UpsertLedger", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inZone := &zap.Zone{}
		outZones, err := storage.UpdateZone(inZone)
		assert.Nil(outZones, "zones should be nil")
		require.Error(t, err)
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			errs := multi.Unwrap()
			isErr := test.Error1.Error() == errs[0].Error()
			assert.True(isErr, "error should be equal")
		}
	}
}

// TestUpdateZoneWithSuccess tests the UpdateZone function with success.
func TestUpdateZoneWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()

	dbOutZone := &repos.Zone{
		ZoneID:    232956849236,
		Name:      "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertZone", mock.Anything, false, mock.Anything).Return(dbOutZone, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inZone := &zap.Zone{}
	outZones, err := storage.UpdateZone(inZone)
	require.NoError(t, err, "error should be nil")
	assert.NotNil(outZones, "zones should not be nil")
	assert.Equal(dbOutZone.ZoneID, outZones.ZoneID, "zone id should be equal")
	assert.Equal(dbOutZone.Name, outZones.Name, "zone name should be equal")
	assert.Equal(dbOutZone.CreatedAt, outZones.CreatedAt, "created at should be equal")
	assert.Equal(dbOutZone.UpdatedAt, outZones.UpdatedAt, "updated at should be equal")
}

// TestDeleteZoneWithErrors tests the DeleteZone function with errors.
func TestDeleteZoneWithErrors(t *testing.T) {
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
			mockSQLRepo.On("DeleteZone", mock.Anything, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteZone", mock.Anything, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inZoneID := int64(232956849236)
		outZones, err := storage.DeleteZone(inZoneID)
		assert.Nil(outZones, "zones should be nil")
		require.Error(t, err)
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			errs := multi.Unwrap()
			isErr := test.Error1.Error() == errs[0].Error()
			assert.True(isErr, "error should be equal")
		}
	}
}

// TestDeleteZoneWithSuccess tests the DeleteZone function with success.
func TestDeleteZoneWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteZAPCentralStorageWithMocks()

	dbOutZone := &repos.Zone{
		ZoneID:    232956849236,
		Name:      "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("DeleteZone", mock.Anything, mock.Anything).Return(dbOutZone, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inZoneID := int64(232956849236)
	outZones, err := storage.DeleteZone(inZoneID)
	require.NoError(t, err, "error should be nil")
	assert.NotNil(outZones, "zones should not be nil")
	assert.Equal(dbOutZone.ZoneID, outZones.ZoneID, "zone id should be equal")
	assert.Equal(dbOutZone.Name, outZones.Name, "zone name should be equal")
	assert.Equal(dbOutZone.CreatedAt, outZones.CreatedAt, "created at should be equal")
	assert.Equal(dbOutZone.UpdatedAt, outZones.UpdatedAt, "updated at should be equal")
}

// TestFetchZoneWithErrors tests the FetchZone function with errors.
func TestFetchZoneWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, _, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New("operation error"))
		outZones, err := storage.FetchZones(1, 100, nil)
		assert.Nil(outZones, "zones should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outZones, err := storage.FetchZones(0, 100, nil)
		assert.Nil(outZones, "zones should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with invalid page size
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outZones, err := storage.FetchZones(1, 0, nil)
		assert.Nil(outZones, "zones should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with invalid zone id
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outZones, err := storage.FetchZones(1, 100, map[string]any{zap.FieldZoneZoneID: "not valid"})
		assert.Nil(outZones, "zones should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with invalid zone name
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outZones, err := storage.FetchZones(1, 100, map[string]any{zap.FieldZoneName: 2})
		assert.Nil(outZones, "zones should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with invalid zone name
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		mockSQLRepo.On("FetchZones", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("operation error"))
		outZones, err := storage.FetchZones(1, 100, nil)
		assert.Nil(outZones, "zones should be nil")
		require.Error(t, err, "error should not be nil")
	}
}

// TestFetchZoneWithSuccess tests the DeleteZone function with success.
func TestFetchZoneWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteZAPCentralStorageWithMocks()

	dbOutZones := []repos.Zone{
		{
			ZoneID:    232956849236,
			Name:      "rent-a-car1",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ZoneID:    506074038324,
			Name:      "rent-a-car2",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLRepo.On("FetchZones", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbOutZones, nil)

	outZones, err := storage.FetchZones(1, 100, map[string]any{zap.FieldZoneZoneID: int64(506074038324), zap.FieldZoneName: "rent-a-car2"})
	require.NoError(t, err, "error should be nil")
	assert.NotNil(outZones, "zones should not be nil")
	assert.Len(outZones, len(dbOutZones), "zones  and dbZones should have the same length")
	for i, outZone := range outZones {
		assert.Equal(dbOutZones[i].ZoneID, outZone.ZoneID, "zone id should be equal")
		assert.Equal(dbOutZones[i].Name, outZone.Name, "zone name should be equal")
		assert.Equal(dbOutZones[i].CreatedAt, outZone.CreatedAt, "created at should be equal")
		assert.Equal(dbOutZones[i].UpdatedAt, outZone.UpdatedAt, "updated at should be equal")
	}
}
