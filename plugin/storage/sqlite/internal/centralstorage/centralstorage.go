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
	"database/sql"

	"github.com/jmoiron/sqlx"

	"github.com/permguard/permguard/pkg/agents/storage"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	"github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
)

type SqliteRepo interface {
	// UpsertZone creates or updates a zone.
	UpsertZone(tx *sql.Tx, isCreate bool, zone *repos.Zone) (*repos.Zone, error)
	// DeleteZone deletes a zone.
	DeleteZone(tx *sql.Tx, zoneID int64) (*repos.Zone, error)
	// FetchZone fetches a zone.
	FetchZones(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]repos.Zone, error)

	// UpsertIdentitySource creates or updates an identity source.
	UpsertIdentitySource(tx *sql.Tx, isCreate bool, identitySource *repos.IdentitySource) (*repos.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(tx *sql.Tx, zoneID int64, identitySourceID string) (*repos.IdentitySource, error)
	// FetchIdentitySources fetches identity sources.
	FetchIdentitySources(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]repos.IdentitySource, error)

	// UpsertIdentity creates or updates an identity.
	UpsertIdentity(tx *sql.Tx, isCreate bool, identity *repos.Identity) (*repos.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(tx *sql.Tx, zoneID int64, identityID string) (*repos.Identity, error)
	// FetchIdentities fetches identities.
	FetchIdentities(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]repos.Identity, error)

	// UpsertTenant creates or updates an tenant.
	UpsertTenant(tx *sql.Tx, isCreate bool, tenant *repos.Tenant) (*repos.Tenant, error)
	// DeleteTenant deletes an tenant.
	DeleteTenant(tx *sql.Tx, zoneID int64, tenantID string) (*repos.Tenant, error)
	// FetchTenant fetches an tenant.
	FetchTenants(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]repos.Tenant, error)

	// UpsertLedger creates or updates a ledger.
	UpsertLedger(tx *sql.Tx, isCreate bool, ledger *repos.Ledger) (*repos.Ledger, error)
	// DeleteLedger deletes a ledger.
	DeleteLedger(tx *sql.Tx, zoneID int64, ledgerID string) (*repos.Ledger, error)
	// FetchLedgers fetches ledgers.
	FetchLedgers(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]repos.Ledger, error)
	// UpdateLedgerRef updates the ledger ref.
	UpdateLedgerRef(tx *sql.Tx, zoneID int64, ledgerID, currentRef, newRef string) error

	// UpsertKeyValue creates or updates a key value.
	UpsertKeyValue(tx *sql.Tx, keyValue *repos.KeyValue) (*repos.KeyValue, error)
	// DeleteKeyValue deletes a key value.
	KeyValue(db *sqlx.DB, zoneID int64, key string) (*repos.KeyValue, error)
}

// SqliteExecutor is the interface for executing sqlite commands.
type SqliteExecutor interface {
	// Connect connects to the sqlite database.
	Connect(ctx *storage.StorageContext, sqliteConnector db.SQLiteConnector) (*sqlx.DB, error)
}

// SqliteExec implements the SqliteExecutor interface.
type SqliteExec struct {
}

// Connect connects to the sqlite database.
func (s SqliteExec) Connect(ctx *storage.StorageContext, sqliteConnector db.SQLiteConnector) (*sqlx.DB, error) {
	logger := ctx.Logger()
	db, err := sqliteConnector.Connect(logger, ctx)
	if err != nil {
		return nil, repos.WrapSqlite3Error("cannot connect to sqlite", err)
	}
	return db, nil
}

// SQLiteCentralStorage implements the sqlite central storage.
type SQLiteCentralStorage struct {
	ctx             *storage.StorageContext
	sqliteConnector db.SQLiteConnector
}

// NewSQLiteCentralStorage creates a new sqlite central storage.
func NewSQLiteCentralStorage(storageContext *storage.StorageContext, sqliteConnector db.SQLiteConnector) (*SQLiteCentralStorage, error) {
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
