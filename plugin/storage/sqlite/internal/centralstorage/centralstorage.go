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
	// UpsertAccount creates or updates an account.
	UpsertAccount(tx *sql.Tx, isCreate bool, account *azirepos.Account) (*azirepos.Account, error)
	// DeleteAccount deletes an account.
	DeleteAccount(tx *sql.Tx, accountID int64) (*azirepos.Account, error)
	// FetchAccount fetches an account.
	FetchAccounts(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]azirepos.Account, error)

	// UpsertIdentitySource creates or updates an identity source.
	UpsertIdentitySource(tx *sql.Tx, isCreate bool, identitySource *azirepos.IdentitySource) (*azirepos.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(tx *sql.Tx, accountID int64, identitySourceID string) (*azirepos.IdentitySource, error)
	// FetchIdentitySources fetches identity sources.
	FetchIdentitySources(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]azirepos.IdentitySource, error)

	// UpsertIdentity creates or updates an identity.
	UpsertIdentity(tx *sql.Tx, isCreate bool, identity *azirepos.Identity) (*azirepos.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(tx *sql.Tx, accountID int64, identityID string) (*azirepos.Identity, error)
	// FetchIdentities fetches identities.
	FetchIdentities(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]azirepos.Identity, error)

	// UpsertTenant creates or updates an tenant.
	UpsertTenant(tx *sql.Tx, isCreate bool, tenant *azirepos.Tenant) (*azirepos.Tenant, error)
	// DeleteTenant deletes an tenant.
	DeleteTenant(tx *sql.Tx, accountID int64, tenantID string) (*azirepos.Tenant, error)
	// FetchTenant fetches an tenant.
	FetchTenants(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]azirepos.Tenant, error)

	// UpsertRepository creates or updates a repository.
	UpsertRepository(tx *sql.Tx, isCreate bool, repository *azirepos.Repository) (*azirepos.Repository, error)
	// DeleteRepository deletes a repository.
	DeleteRepository(tx *sql.Tx, accountID int64, repositoryID string) (*azirepos.Repository, error)
	// FetchRepositories fetches repositories.
	FetchRepositories(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]azirepos.Repository, error)

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
		return nil, azirepos.WrapSqlite3Error("cannot connect to sqlite.", err)
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
	//TODO: Implement logic to get a storage configuration from the storageContext.GetServiceConfigReader()
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
