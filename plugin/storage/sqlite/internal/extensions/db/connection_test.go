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

package db

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	// "github.com/stretchr/testify/mock"
	// "gorm.io/driver/sqlite"
	// "gorm.io/gorm"
	// "gorm.io/gorm/logger"
	// azstorage "github.com/permguard/permguard/pkg/agents/storage"
	// azmocks "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db/mocks"
)

// newSQLiteConnectionMock creates a new SQLiteConnection mock with a mock sqlx.DB and sqlx.DB.
func newSQLiteConnectionMock(t *testing.T) (SQLiteConnector, *sqlx.DB, *sqlx.DB, sqlmock.Sqlmock) {
	// logger := logger.Default.LogMode(logger.Info)

	// sqlDB, sqlMock, err := sqlmock.New()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// gormDB, err := gorm.Open(sqlite.New(sqlite.Config{
	// 	Conn: sqlDB,
	// }), &gorm.Config{
	// 	Logger: logger,
	// })

	// if err != nil {
	// 	t.Fatal(err)
	// }
	// sqlConnMock := azmocks.NewSQLiteConnectionMock()
	// sqlConnMock.On("GetStorage").Return(azstorage.StorageSQLite)
	// sqlConnMock.On("Connect", mock.Anything, mock.Anything).Return(gormDB, nil)
	// sqlConnMock.On("Close", gormDB).Return(nil)
	// return sqlConnMock, sqlDB, gormDB, sqlMock
	return nil, nil, nil, nil
}
