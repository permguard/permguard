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

	"github.com/permguard/permguard/pkg/transport/models/pap"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// TestCreateLedgerWithErrors tests the CreateLedger function with errors.
func TestCreateLedgerWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil ledger
		storage, _, _, _, _, _, _ := createSQLitePAPCentralStorageWithMocks()
		ledgers, err := storage.CreateLedger(nil)
		assert.Nil(ledgers, "ledgers should be nil")
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
			mockSQLRepo.On("UpsertLedger", mock.Anything, true, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertLedger", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inLedger := &pap.Ledger{}
		outLedgers, err := storage.CreateLedger(inLedger)
		assert.Nil(outLedgers, "ledgers should be nil")
		require.Error(t, err)
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			errs := multi.Unwrap()
			isErr := test.Error1.Error() == errs[0].Error()
			assert.True(isErr, "error should be equal")
		}
	}
}

// TestCreateLedgerWithSuccess tests the CreateLedger function with success.
func TestCreateLedgerWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLitePAPCentralStorageWithMocks()

	dbOutLedger := &repos.Ledger{
		ZoneID:    232956849236,
		LedgerID:  repos.GenerateUUID(),
		Name:      "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertLedger", mock.Anything, true, mock.Anything).Return(dbOutLedger, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inLedger := &pap.Ledger{}
	outLedgers, err := storage.CreateLedger(inLedger)
	require.NoError(t, err, "error should be nil")
	assert.NotNil(outLedgers, "ledgers should not be nil")
	assert.Equal(dbOutLedger.LedgerID, outLedgers.LedgerID, "ledger id should be equal")
	assert.Equal(dbOutLedger.Name, outLedgers.Name, "ledger name should be equal")
	assert.Equal(dbOutLedger.CreatedAt, outLedgers.CreatedAt, "created at should be equal")
	assert.Equal(dbOutLedger.UpdatedAt, outLedgers.UpdatedAt, "updated at should be equal")
}

// TestUpdateLedgerWithErrors tests the UpdateLedger function with errors.
func TestUpdateLedgerWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil ledger
		storage, _, _, _, _, _, _ := createSQLitePAPCentralStorageWithMocks()
		ledgers, err := storage.UpdateLedger(nil)
		assert.Nil(ledgers, "ledgers should be nil")
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
			mockSQLRepo.On("UpsertLedger", mock.Anything, false, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertLedger", mock.Anything, false, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inLedger := &pap.Ledger{}
		inLedger.Kind = repos.LedgerTypePolicy
		outLedgers, err := storage.UpdateLedger(inLedger)
		assert.Nil(outLedgers, "ledgers should be nil")
		require.Error(t, err)
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			errs := multi.Unwrap()
			isErr := test.Error1.Error() == errs[0].Error()
			assert.True(isErr, "error should be equal")
		}
	}
}

// TestUpdateLedgerWithSuccess tests the UpdateLedger function with success.
func TestUpdateLedgerWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLitePAPCentralStorageWithMocks()

	dbOutLedger := &repos.Ledger{
		ZoneID:    232956849236,
		LedgerID:  repos.GenerateUUID(),
		Name:      "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertLedger", mock.Anything, false, mock.Anything).Return(dbOutLedger, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inLedger := &pap.Ledger{}
	inLedger.Kind = repos.LedgerTypePolicy

	outLedgers, err := storage.UpdateLedger(inLedger)
	require.NoError(t, err, "error should be nil")
	assert.NotNil(outLedgers, "ledgers should not be nil")
	assert.Equal(dbOutLedger.LedgerID, outLedgers.LedgerID, "ledger id should be equal")
	assert.Equal(dbOutLedger.Name, outLedgers.Name, "ledger name should be equal")
	assert.Equal(dbOutLedger.CreatedAt, outLedgers.CreatedAt, "created at should be equal")
	assert.Equal(dbOutLedger.UpdatedAt, outLedgers.UpdatedAt, "updated at should be equal")
}

// TestDeleteLedgerWithErrors tests the DeleteLedger function with errors.
func TestDeleteLedgerWithErrors(t *testing.T) {
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
			mockSQLRepo.On("DeleteLedger", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteLedger", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inLedgerID := repos.GenerateUUID()
		outLedgers, err := storage.DeleteLedger(repos.GenerateZoneID(), inLedgerID)
		assert.Nil(outLedgers, "ledgers should be nil")
		require.Error(t, err)
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			errs := multi.Unwrap()
			isErr := test.Error1.Error() == errs[0].Error()
			assert.True(isErr, "error should be equal")
		}
	}
}

// TestDeleteLedgerWithSuccess tests the DeleteLedger function with success.
func TestDeleteLedgerWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLitePAPCentralStorageWithMocks()

	dbOutLedger := &repos.Ledger{
		ZoneID:    232956849236,
		LedgerID:  repos.GenerateUUID(),
		Name:      "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("DeleteLedger", mock.Anything, mock.Anything, mock.Anything).Return(dbOutLedger, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inLedgerID := repos.GenerateUUID()
	outLedgers, err := storage.DeleteLedger(repos.GenerateZoneID(), inLedgerID)
	require.NoError(t, err, "error should be nil")
	assert.NotNil(outLedgers, "ledgers should not be nil")
	assert.Equal(dbOutLedger.LedgerID, outLedgers.LedgerID, "ledger id should be equal")
	assert.Equal(dbOutLedger.Name, outLedgers.Name, "ledger name should be equal")
	assert.Equal(dbOutLedger.CreatedAt, outLedgers.CreatedAt, "created at should be equal")
	assert.Equal(dbOutLedger.UpdatedAt, outLedgers.UpdatedAt, "updated at should be equal")
}

// TestFetchLedgerWithErrors tests the FetchLedger function with errors.
func TestFetchLedgerWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, _, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, errors.New("operation error"))
		outLedgers, err := storage.FetchLedgers(1, 100, 232956849236, nil)
		assert.Nil(outLedgers, "ledgers should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outLedgers, err := storage.FetchLedgers(0, 100, 232956849236, nil)
		assert.Nil(outLedgers, "ledgers should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with invalid page size
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outLedgers, err := storage.FetchLedgers(1, 0, 232956849236, nil)
		assert.Nil(outLedgers, "ledgers should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with invalid ledger id
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outLedgers, err := storage.FetchLedgers(1, 100, 232956849236, map[string]any{pap.FieldLedgerLedgerID: 232956849236})
		assert.Nil(outLedgers, "ledgers should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with invalid ledger name
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outLedgers, err := storage.FetchLedgers(1, 100, 232956849236, map[string]any{pap.FieldLedgerName: 2})
		assert.Nil(outLedgers, "ledgers should be nil")
		require.Error(t, err, "error should not be nil")
	}

	{ // Test with server error
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		mockSQLRepo.On("FetchLedgers", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("operation error"))
		outLedgers, err := storage.FetchLedgers(1, 100, 232956849236, nil)
		assert.Nil(outLedgers, "ledgers should be nil")
		require.Error(t, err, "error should not be nil")
	}
}

// TestFetchLedgerWithSuccess tests the FetchLedger function with success.
func TestFetchLedgerWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLitePAPCentralStorageWithMocks()

	dbOutLedgers := []repos.Ledger{
		{
			ZoneID:    232956849236,
			LedgerID:  repos.GenerateUUID(),
			Name:      "rent-a-car1",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ZoneID:    232956849236,
			LedgerID:  repos.GenerateUUID(),
			Name:      "rent-a-car2",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLRepo.On("FetchLedgers", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbOutLedgers, nil)

	outLedgers, err := storage.FetchLedgers(1, 100, 232956849236, map[string]any{pap.FieldLedgerLedgerID: repos.GenerateUUID(), pap.FieldLedgerName: "rent-a-car2"})
	require.NoError(t, err, "error should be nil")
	assert.NotNil(outLedgers, "ledgers should not be nil")
	assert.Len(dbOutLedgers, len(outLedgers), "ledgers and dbLedgers should have the same length")
	for i, outLedger := range outLedgers {
		assert.Equal(dbOutLedgers[i].LedgerID, outLedger.LedgerID, "ledger id should be equal")
		assert.Equal(dbOutLedgers[i].Name, outLedger.Name, "ledger name should be equal")
		assert.Equal(dbOutLedgers[i].CreatedAt, outLedger.CreatedAt, "created at should be equal")
		assert.Equal(dbOutLedgers[i].UpdatedAt, outLedger.UpdatedAt, "updated at should be equal")
	}
}
