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

// Package mocks implements mocks for testing.
package mocks

import (
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

type MockSQLiteConnector struct {
	mock sqlmock.Sqlmock
	db   *sqlx.DB
}

func NewMockSQLiteConnector() (*MockSQLiteConnector, error) {
	db, mock, err := sqlmock.New()
	if err != nil {
		return nil, err
	}

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	return &MockSQLiteConnector{
		mock: mock,
		db:   sqlxDB,
	}, nil
}

func (m *MockSQLiteConnector) GetStorage() azstorage.StorageKind {
	return azstorage.StorageSQLite
}

func (m *MockSQLiteConnector) Connect(logger *zap.Logger, ctx *azstorage.StorageContext) (*sqlx.DB, error) {
	// In un contesto reale, dovresti gestire la connessione al DB qui.
	// Poiché stai usando go-sqlmock, restituirai semplicemente il DB mockato.
	return m.db, nil
}

func (m *MockSQLiteConnector) Disconnect(logger *zap.Logger, ctx *azstorage.StorageContext) error {
	// In un contesto reale, dovresti gestire la disconnessione qui.
	// Poiché stai usando go-sqlmock, puoi semplicemente chiudere il mock DB.
	return m.db.Close()
}
