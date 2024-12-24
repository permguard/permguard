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

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	azidb "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
)

type SqliteRepo interface {
	// UpsertApplication creates or updates an application.
	UpsertApplication(tx *sql.Tx, isCreate bool, application *azirepos.Application) (*azirepos.Application, error)
	// DeleteApplication deletes an application.
	DeleteApplication(tx *sql.Tx, applicationID int64) (*azirepos.Application, error)
	// FetchApplication fetches an application.
	FetchApplications(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]azirepos.Application, error)

	// UpsertIdentitySource creates or updates an identity source.
	UpsertIdentitySource(tx *sql.Tx, isCreate bool, identitySource *azirepos.IdentitySource) (*azirepos.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(tx *sql.Tx, applicationID int64, identitySourceID string) (*azirepos.IdentitySource, error)
	// FetchIdentitySources fetches identity sources.
	FetchIdentitySources(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]azirepos.IdentitySource, error)

	// UpsertIdentity creates or updates an identity.
	UpsertIdentity(tx *sql.Tx, isCreate bool, identity *azirepos.Identity) (*azirepos.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(tx *sql.Tx, applicationID int64, identityID string) (*azirepos.Identity, error)
	// FetchIdentities fetches identities.
	FetchIdentities(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]azirepos.Identity, error)

	// UpsertTenant creates or updates an tenant.
	UpsertTenant(tx *sql.Tx, isCreate bool, tenant *azirepos.Tenant) (*azirepos.Tenant, error)
	// DeleteTenant deletes an tenant.
	DeleteTenant(tx *sql.Tx, applicationID int64, tenantID string) (*azirepos.Tenant, error)
	// FetchTenant fetches an tenant.
	FetchTenants(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]azirepos.Tenant, error)

	// UpsertLedger creates or updates a ledger.
	UpsertLedger(tx *sql.Tx, isCreate bool, ledger *azirepos.Ledger) (*azirepos.Ledger, error)
	// DeleteLedger deletes a ledger.
	DeleteLedger(tx *sql.Tx, applicationID int64, ledgerID string) (*azirepos.Ledger, error)
	// FetchLedgers fetches ledgers.
	FetchLedgers(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]azirepos.Ledger, error)
	// UpdateLedgerRef updates the ledger ref.
	UpdateLedgerRef(tx *sql.Tx, applicationID int64, ledgerID, currentRef, newRef string) error

	// UpsertKeyValue creates or updates a key value.
	UpsertKeyValue(tx *sql.Tx, keyValue *azirepos.KeyValue) (*azirepos.KeyValue, error)
	// DeleteKeyValue deletes a key value.
	GetKeyValue(db *sqlx.DB, key string) (*azirepos.KeyValue, error)
}

// SqliteExecutor is the interface for executing sqlite commands.
type SqliteExecutor interface {
	// Connect connects to the sqlite database.
	Connect(ctx *azstorage.StorageContext, sqliteConnector azidb.SQLiteConnector) (*sqlx.DB, error)
}

// SqliteExec implements the SqliteExecutor interface.
type SqliteExec struct {
}

// Connect connects to the sqlite database.
func (s SqliteExec) Connect(ctx *azstorage.StorageContext, sqliteConnector azidb.SQLiteConnector) (*sqlx.DB, error) {
	logger := ctx.GetLogger()
	db, err := sqliteConnector.Connect(logger, ctx)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error("cannot connect to sqlite", err)
	}
	return db, nil
}

// SQLiteCentralStorage implements the sqlite central storage.
type SQLiteCentralStorage struct {
	ctx             *azstorage.StorageContext
	sqliteConnector azidb.SQLiteConnector
}

// NewSQLiteCentralStorage creates a new sqlite central storage.
func NewSQLiteCentralStorage(storageContext *azstorage.StorageContext, sqliteConnector azidb.SQLiteConnector) (*SQLiteCentralStorage, error) {
	return &SQLiteCentralStorage{
		ctx:             storageContext,
		sqliteConnector: sqliteConnector,
	}, nil
}

// GetAAPCentralStorage returns the AAP central storage.
func (s SQLiteCentralStorage) GetAAPCentralStorage() (azstorage.AAPCentralStorage, error) {
	return newSQLiteAAPCentralStorage(s.ctx, s.sqliteConnector, nil, nil)
}

// GetPAPCentralStorage returns the PAP central storage.
func (s SQLiteCentralStorage) GetPAPCentralStorage() (azstorage.PAPCentralStorage, error) {
	return newSQLitePAPCentralStorage(s.ctx, s.sqliteConnector, nil, nil)
}
