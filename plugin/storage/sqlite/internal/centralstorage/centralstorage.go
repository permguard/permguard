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
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"

	"github.com/permguard/permguard/pkg/agents/storage"
	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	"github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
)

// SqliteRepo is the interface for sqlite repository operations.
type SqliteRepo interface {
	// UpsertZone creates or updates a zone.
	UpsertZone(ctx context.Context, tx *sql.Tx, isCreate bool, zone *azrepos.Zone) (*azrepos.Zone, error)
	// DeleteZone deletes a zone.
	DeleteZone(ctx context.Context, tx *sql.Tx, zoneID int64) (*azrepos.Zone, error)
	// FetchZone fetches a zone.
	FetchZones(ctx context.Context, db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]azrepos.Zone, error)

	// UpsertLedger creates or updates a ledger.
	UpsertLedger(ctx context.Context, tx *sql.Tx, isCreate bool, ledger *azrepos.Ledger) (*azrepos.Ledger, error)
	// DeleteLedger deletes a ledger.
	DeleteLedger(ctx context.Context, tx *sql.Tx, zoneID int64, ledgerID string) (*azrepos.Ledger, error)
	// FetchLedgers fetches ledgers.
	FetchLedgers(ctx context.Context, db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]azrepos.Ledger, error)
	// UpdateLedgerRef updates the ledger ref.
	UpdateLedgerRef(ctx context.Context, tx *sql.Tx, zoneID int64, ledgerID, currentRef, newRef string) error

	// UpsertKeyValue creates or updates a key value.
	UpsertKeyValue(ctx context.Context, tx *sql.Tx, keyValue *azrepos.KeyValue) (*azrepos.KeyValue, error)
	// KeyValue retrieves a key value.
	KeyValue(ctx context.Context, db *sqlx.DB, zoneID int64, key string) (*azrepos.KeyValue, error)
	// KeyValueTx retrieves a key value within a transaction.
	KeyValueTx(ctx context.Context, tx *sql.Tx, zoneID int64, key string) (*azrepos.KeyValue, error)
}

// SqliteExecutor is the interface for executing sqlite commands.
type SqliteExecutor interface {
	// Connect connects to the sqlite database.
	Connect(ctx *storage.Context, sqliteConnector db.SQLiteConnector) (*sqlx.DB, error)
}

// SqliteExec implements the SqliteExecutor interface.
type SqliteExec struct{}

// Connect connects to the sqlite database.
func (s SqliteExec) Connect(ctx *storage.Context, sqliteConnector db.SQLiteConnector) (*sqlx.DB, error) {
	logger := ctx.Logger()
	db, err := sqliteConnector.Connect(logger, ctx)
	if err != nil {
		return nil, azrepos.WrapSqliteError("cannot connect to sqlite", err)
	}
	return db, nil
}

// SQLiteCentralStorage implements the sqlite central storage.
type SQLiteCentralStorage struct {
	ctx             *storage.Context
	sqliteConnector db.SQLiteConnector
}

// NewSQLiteCentralStorage creates a new sqlite central storage.
func NewSQLiteCentralStorage(storageContext *storage.Context, sqliteConnector db.SQLiteConnector) (*SQLiteCentralStorage, error) {
	return &SQLiteCentralStorage{
		ctx:             storageContext,
		sqliteConnector: sqliteConnector,
	}, nil
}

// ZAPCentralStorage returns the ZAP central storage.
func (s SQLiteCentralStorage) ZAPCentralStorage() (storage.ZAPCentralStorage, error) {
	return newSQLiteZAPCentralStorage(s.ctx, s.sqliteConnector, nil, nil)
}

// PAPCentralStorage returns the PAP central storage.
func (s SQLiteCentralStorage) PAPCentralStorage() (storage.PAPCentralStorage, error) {
	return newSQLitePAPCentralStorage(s.ctx, s.sqliteConnector, nil, nil)
}

// PDPCentralStorage returns the PDP central storage.
func (s SQLiteCentralStorage) PDPCentralStorage() (storage.PDPCentralStorage, error) {
	return newSQLitePDPCentralStorage(s.ctx, s.sqliteConnector, nil, nil)
}
