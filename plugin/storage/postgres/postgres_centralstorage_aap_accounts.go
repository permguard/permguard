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
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// CreateAccount creates a new account.
func (s PostgresCentralStorageAAP) upsertAccount(db *gorm.DB, isCreate bool, account *azmodels.Account) (*azmodels.Account, error) {
	if account == nil {
		return nil, fmt.Errorf("storage: %w", azerrors.ErrInvalidInputParameter)
	}
	if !isCreate {
		if err := validateAccountID("account", account.AccountID); err != nil {
			return nil, fmt.Errorf("storage: invalid account id %d. %w", account.AccountID, azerrors.ErrClientAccountID)
		}
	}
	if err := validateName("account", account.Name); err != nil {
		return nil, fmt.Errorf("storage: invalid account name %q. %w", account.Name, azerrors.ErrClientName)
	}

	var dbAccount Account
	var result *gorm.DB
	if isCreate {
		dbAccount = Account{
			Name: account.Name,
		}
		tx := db.Begin()
		result = tx.Omit("CreatedAt", "UpdatedAt").Create(&dbAccount)
		if result.RowsAffected == 0 || result.Error != nil {
			tx.Rollback()
			pgErr, ok := result.Error.(*pgconn.PgError)
			if ok && pgErr.Code == "23505" {
				return nil, fmt.Errorf("storage: account cannot be created because of a duplicated name %w", azerrors.ErrStorageDuplicate)
			}
			return nil, fmt.Errorf("storage: account cannot be created. %w", azerrors.ErrStorageGeneric)
		}
		_, err := s.upsertTenant(tx, true, &azmodels.Tenant{Name: TenantDefaultName, AccountID: dbAccount.AccountID})
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("storage: account cannot be created because of the tenant creation. %w", azerrors.ErrStorageGeneric)
		}
		_, err = s.upsertIdentitySource(tx, true, &azmodels.IdentitySource{Name: IdentitySourceDefaultName, AccountID: dbAccount.AccountID})
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("storage: account cannot be created because of the identity source creation. %w", azerrors.ErrStorageGeneric)
		}
		tx.Commit()
	} else {
		result = db.Where("account_id = ?", account.AccountID).First(&dbAccount)
		if result.RowsAffected == 0 {
			return nil, fmt.Errorf("storage: account cannot be retrieved. %w", azerrors.ErrStorageNotFound)
		}
		dbAccount.Name = account.Name
		result = db.Omit("CreatedAt", "UpdatedAt").Where("account_id = ?", account.AccountID).Updates(account)
		if result.RowsAffected == 0 || result.Error != nil {
			pgErr, ok := result.Error.(*pgconn.PgError)
			if ok && pgErr.Code == "23505" {
				return nil, fmt.Errorf("storage: account cannot be updated because of a duplicated name %w", azerrors.ErrStorageDuplicate)
			}
			return nil, fmt.Errorf("storage: account cannot be updated. %w", azerrors.ErrStorageGeneric)
		}
	}
	return mapAccountToAgentAccount(&dbAccount)
}

// CreateAccount creates a new account.
func (s PostgresCentralStorageAAP) CreateAccount(account *azmodels.Account) (*azmodels.Account, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertAccount(db, true, account)
}

// UpdateAccount updates an account.
func (s PostgresCentralStorageAAP) UpdateAccount(account *azmodels.Account) (*azmodels.Account, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertAccount(db, false, account)
}

// DeleteAccount deletes an account.
func (s PostgresCentralStorageAAP) DeleteAccount(accountID int64) (*azmodels.Account, error) {
	if err := validateAccountID("account", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	var dbAccount Account
	result := db.Where("account_id = ?", accountID).First(&dbAccount)
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("storage: account cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	result = db.Delete(dbAccount)
	if result.RowsAffected == 0 || result.Error != nil {
		return nil, fmt.Errorf("storage: account cannot be deleted. %w", azerrors.ErrStorageGeneric)
	}
	return mapAccountToAgentAccount(&dbAccount)
}

// GetAllAccounts returns all accounts.
func (s PostgresCentralStorageAAP) GetAllAccounts(fields map[string]any) ([]azmodels.Account, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}

	var dbAccounts []Account
	query := db
	if _, ok := fields[azmodels.FieldAccountAccountID]; ok {
		accountID, ok := fields[azmodels.FieldAccountAccountID].(int64)
		if !ok {
			return nil, fmt.Errorf("storage: invalid account id. %w", azerrors.ErrClientAccountID)
		}
		if err := validateAccountID("account", accountID); err != nil {
			return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
		}
		query = query.Where("account_id = ?", accountID)
	}
	if _, ok := fields[azmodels.FieldAccountName]; ok {
		name, ok := fields[azmodels.FieldAccountName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid account name. %w", azerrors.ErrClientName)
		}
		if err := validateName("account", name); err != nil {
			return nil, fmt.Errorf("storage: invalid account name %q. %w", name, azerrors.ErrClientName)
		}
		name = "%" + name + "%"
		query = query.Where("name LIKE ?", name)
	}
	result := query.Find(&dbAccounts)
	if result.Error != nil {
		return nil, fmt.Errorf("storage: accounts cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	dbAllAccounts := make([]azmodels.Account, len(dbAccounts))
	for i, a := range dbAccounts {
		account, err := mapAccountToAgentAccount(&a)
		if err != nil {
			return nil, fmt.Errorf("storage: accounts cannot be converted. %w", azerrors.ErrServerGeneric)
		}
		dbAllAccounts[i] = *account
	}
	return dbAllAccounts, nil
}
