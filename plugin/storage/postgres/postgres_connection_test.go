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

package postgres

import (
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/mock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azmocks "github.com/permguard/permguard/plugin/storage/postgres/mocks"
)

// newPostgresConnectionMock creates a new PostgresConnection mock with a mock sql.DB and gorm.DB.
func newPostgresConnectionMock(t *testing.T) (PostgresConnector, *sql.DB, *gorm.DB, sqlmock.Sqlmock) {
	logger := logger.Default.LogMode(logger.Info)

	sqlDB, sqlMock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: sqlDB,
	}), &gorm.Config{
		Logger: logger,
	})

	if err != nil {
		t.Fatal(err)
	}
	pgConnMock := azmocks.NewPostgresConnectionMock()
	pgConnMock.On("GetStorage").Return(azstorage.StoragePostgres)
	pgConnMock.On("Connect", mock.Anything, mock.Anything).Return(gormDB, nil)
	pgConnMock.On("Close", gormDB).Return(nil)
	return pgConnMock, sqlDB, gormDB, sqlMock
}
