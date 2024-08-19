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
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azrtmmocks "github.com/permguard/permguard/pkg/agents/runtime/mocks"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azidbtestutils "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db/testutils"
)

// NewSqliteCentralStorageAAPMock creates a new AAPCentralStorage with a mock sql.DB and sqlx.DB.
func NewSqliteCentralStorageAAPMock(t *testing.T) (azstorage.AAPCentralStorage, *sqlx.DB, *sqlx.DB, sqlmock.Sqlmock) {
	runtimeCtx := azrtmmocks.NewRuntimeContextMock()
	storageCtx, err := azstorage.NewStorageContext(runtimeCtx, azstorage.StorageSQLite)
	if err != nil {
		t.Fatal(err)
	}
	pgConn, sqlDB, gormDB, mock := azidbtestutils.NewSqliteConnectionMocks(t)
	storage, err := NewSQLiteCentralStorage(storageCtx, pgConn)
	if err != nil {
		t.Fatal(err)
	}
	aapStorage, err := storage.GetAAPCentralStorage()
	if err != nil {
		t.Fatal(err)
	}
	return aapStorage, sqlDB, gormDB, mock
}

// registerAccountForInsertMocking registers an account for insert mocking.
func registerAccountForInsertMocking() (*azmodels.Account, string, *sqlmock.Rows) {
	account := &azmodels.Account{
		AccountID: 581616507495,
		Name: "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sql := "INSERT INTO \"accounts\" (.+) VALUES (.+)"
	sqlRows := sqlmock.NewRows([]string{"account_id", "created_at", "updated_at", "name"}).
		AddRow(account.AccountID, account.CreatedAt, account.UpdatedAt, account.Name)
	return account, sql, sqlRows
}
