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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
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
		Error1 error
	}{
		"CONNECT-ERROR": { IsCustomError: true, Error1: azerrors.ErrStorageGeneric },
		"BEGIN-ERROR": { IsCustomError: true, Error1: azerrors.ErrStorageGeneric },
		"ROLLBACK-ERROR": { IsCustomError: false, Error1: errors.New("ROLLBACK-ERROR") },
		"COMMIT-ERROR": { IsCustomError: true, Error1: azerrors.ErrStorageGeneric },
	}
	for testcase, test := range tests {
		storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlDB, mockSQLDB := createSQLiteAAPCentralStorageWithMocks()
		inAccount := &azmodels.Account{}
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

		accounts, err := storage.CreateAccount(inAccount)
		assert.Nil(accounts, "accounts should be nil")
		assert.Error(err)
		if test.IsCustomError {
			assert.True(azerrors.AreErrorsEqual(err, test.Error1), "error should be equal")
		} else {
			assert.Equal(test.Error1, err, "error should be equal")
		}
	}
}