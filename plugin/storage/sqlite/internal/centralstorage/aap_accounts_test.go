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
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// TestCreateAccountWithErrors tests the CreateAccount function with errors.
func TestCreateAccountWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil account
		storage, _, _, _, _, _, _ := createSQLiteAAPCentralStorageWithMocks()
		accounts, err := storage.CreateAccount(nil)
		assert.Nil(accounts, "accounts should be nil")
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
			mockSQLRepo.On("UpsertAccount", mock.Anything, true, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertAccount", mock.Anything, true, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inAccount := &azmodels.Account{}
		outAccounts, err := storage.CreateAccount(inAccount)
		assert.Nil(outAccounts, "accounts should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestCreateAccountWithSuccess tests the CreateAccount function with success.
func TestCreateAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()

	dbOutAccount := &azirepos.Account{
		AccountID: 232956849236,
		Name: "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertAccount", mock.Anything, true, mock.Anything).Return(dbOutAccount, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inAccount := &azmodels.Account{}
	outAccounts, err := storage.CreateAccount(inAccount)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outAccounts, "accounts should not be nil")
	assert.Equal(dbOutAccount.AccountID, outAccounts.AccountID, "account id should be equal")
	assert.Equal(dbOutAccount.Name, outAccounts.Name, "account name should be equal")
	assert.Equal(dbOutAccount.CreatedAt, outAccounts.CreatedAt, "created at should be equal")
	assert.Equal(dbOutAccount.UpdatedAt, outAccounts.UpdatedAt, "updated at should be equal")
}

// TestUpdateAccountWithErrors tests the UpdateAccount function with errors.
func TestUpdateAccountWithErrors(t *testing.T) {
	assert := assert.New(t)

	{ // Test with nil account
		storage, _, _, _, _, _, _ := createSQLiteAAPCentralStorageWithMocks()
		accounts, err := storage.UpdateAccount(nil)
		assert.Nil(accounts, "accounts should be nil")
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
			mockSQLRepo.On("UpsertAccount", mock.Anything, false, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("UpsertAccount", mock.Anything, false, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inAccount := &azmodels.Account{}
		outAccounts, err := storage.UpdateAccount(inAccount)
		assert.Nil(outAccounts, "accounts should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestUpdateAccountWithSuccess tests the UpdateAccount function with success.
func TestUpdateAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()

	dbOutAccount := &azirepos.Account{
		AccountID: 232956849236,
		Name: "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("UpsertAccount", mock.Anything, false, mock.Anything).Return(dbOutAccount, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inAccount := &azmodels.Account{}
	outAccounts, err := storage.UpdateAccount(inAccount)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outAccounts, "accounts should not be nil")
	assert.Equal(dbOutAccount.AccountID, outAccounts.AccountID, "account id should be equal")
	assert.Equal(dbOutAccount.Name, outAccounts.Name, "account name should be equal")
	assert.Equal(dbOutAccount.CreatedAt, outAccounts.CreatedAt, "created at should be equal")
	assert.Equal(dbOutAccount.UpdatedAt, outAccounts.UpdatedAt, "updated at should be equal")
}

// TestDeleteAccountWithErrors tests the DeleteAccount function with errors.
func TestDeleteAccountWithErrors(t *testing.T) {
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
			mockSQLRepo.On("DeleteAccount", mock.Anything, mock.Anything).Return(nil, errors.New(testcase))
		case "COMMIT-ERROR":
			mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
			mockSQLDB.ExpectBegin()
			mockSQLRepo.On("DeleteAccount", mock.Anything, mock.Anything).Return(nil, nil)
			mockSQLDB.ExpectCommit().WillReturnError(errors.New(testcase))
		default:
			assert.FailNow("Unknown testcase")
		}

		inAccountID :=int64(232956849236)
		outAccounts, err := storage.DeleteAccount(inAccountID)
		assert.Nil(outAccounts, "accounts should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}

// TestDeleteAccountWithSuccess tests the DeleteAccount function with success.
func TestDeleteAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()

	dbOutAccount := &azirepos.Account{
		AccountID: 232956849236,
		Name: "rent-a-car1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLDB.ExpectBegin()
	mockSQLRepo.On("DeleteAccount", mock.Anything, mock.Anything).Return(dbOutAccount, nil)
	mockSQLDB.ExpectCommit().WillReturnError(nil)

	inAccountID :=int64(232956849236)
	outAccounts, err := storage.DeleteAccount(inAccountID)
	assert.Nil(err, "error should be nil")
	assert.NotNil(outAccounts, "accounts should not be nil")
	assert.Equal(dbOutAccount.AccountID, outAccounts.AccountID, "account id should be equal")
	assert.Equal(dbOutAccount.Name, outAccounts.Name, "account name should be equal")
	assert.Equal(dbOutAccount.CreatedAt, outAccounts.CreatedAt, "created at should be equal")
	assert.Equal(dbOutAccount.UpdatedAt, outAccounts.UpdatedAt, "updated at should be equal")
}

// TestFetchAccountWithErrors tests the FetchAccount function with errors.
func TestFetchAccountWithErrors(t *testing.T) {
	assert := assert.New(t)

	{	// Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, _, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(nil, azerrors.ErrServerGeneric)
		outAccounts, err := storage.FetchAccounts(1, 100,nil)
		assert.Nil(outAccounts, "accounts should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrServerGeneric, err), "error should be errservergeneric")
	}

	{	// Test with invalid page
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outAccounts, err := storage.FetchAccounts(0, 100,nil)
		assert.Nil(outAccounts, "accounts should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{	// Test with invalid page size
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outAccounts, err := storage.FetchAccounts(1, 0,nil)
		assert.Nil(outAccounts, "accounts should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{	// Test with invalid account id
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outAccounts, err := storage.FetchAccounts(1, 100, map[string]interface{}{azmodels.FieldAccountAccountID: "not valid"})
		assert.Nil(outAccounts, "accounts should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{	// Test with invalid account name
		storage, mockStorageCtx, mockConnector, _, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		outAccounts, err := storage.FetchAccounts(1, 100, map[string]interface{}{azmodels.FieldAccountName: 2 })
		assert.Nil(outAccounts, "accounts should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}


	{	// Test with invalid account name
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()
		mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
		mockSQLRepo.On("FetchAccounts", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, azerrors.ErrServerGeneric)
		outAccounts, err := storage.FetchAccounts(1, 100, nil)
		assert.Nil(outAccounts, "accounts should be nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrServerGeneric, err), "error should be errservergeneric")
	}
}

// TestFetchAccountWithSuccess tests the DeleteAccount function with success.
func TestFetchAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, _ := createSQLiteAAPCentralStorageWithMocks()

	dbOutAccounts := []azirepos.Account{
		{
			AccountID: 232956849236,
			Name: "rent-a-car1",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			AccountID: 506074038324,
			Name: "rent-a-car2",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	mockSQLExec.On("Connect", mockStorageCtx, mockConnector).Return(sqlDB, nil)
	mockSQLRepo.On("FetchAccounts", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbOutAccounts, nil)

	outAccounts, err := storage.FetchAccounts(1, 100, map[string]interface{}{azmodels.FieldAccountAccountID: int64(506074038324), azmodels.FieldAccountName: "rent-a-car2"})
	assert.Nil(err, "error should be nil")
	assert.NotNil(outAccounts, "accounts should not be nil")
	assert.Equal(len(outAccounts), len(dbOutAccounts), "accounts  and dbAccounts should have the same length")
	for i, outAccount := range outAccounts {
		assert.Equal(dbOutAccounts[i].AccountID, outAccount.AccountID, "account id should be equal")
		assert.Equal(dbOutAccounts[i].Name, outAccount.Name, "account name should be equal")
		assert.Equal(dbOutAccounts[i].CreatedAt, outAccount.CreatedAt, "created at should be equal")
		assert.Equal(dbOutAccounts[i].UpdatedAt, outAccount.UpdatedAt, "updated at should be equal")
	}
}
