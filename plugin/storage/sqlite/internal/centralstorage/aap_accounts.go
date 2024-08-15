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
	"fmt"

	"gorm.io/gorm"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azivalidators "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/validators"
)

// upsertAccount creates or updates an account.
func (s SQLiteCentralStorageAAP) upsertAccount(db *gorm.DB, isCreate bool, account *azmodels.Account) (*azmodels.Account, error) {
	if account == nil {
		return nil, fmt.Errorf("storage: %w", azerrors.ErrInvalidInputParameter)
	}
	if !isCreate {
		if err := azivalidators.ValidateAccountID("account", account.AccountID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientAccountID, fmt.Sprintf("storage: invalid account id %d.", account.AccountID))

		}
	}
	if err := azivalidators.ValidateName("account", account.Name); err != nil {
		if account.AccountID == 0 {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid account name %s (it is required to be lower case).", account.Name))
		} else {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid account name %s for account id %d (it is required to be lower case).", account.Name, account.AccountID))
		}
	}
	return nil, nil
}

// CreateAccount creates a new account.
func (s SQLiteCentralStorageAAP) CreateAccount(account *azmodels.Account) (*azmodels.Account, error) {
	logger := s.ctx.GetLogger()
	db, err := s.sqliteConnector.Connect(logger, context.Background())
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrServerInfrastructure, "storage: cannot connect to sqlite.")
	}
	return s.upsertAccount(db, true, account)
}

// UpdateAccount updates an account.
func (s SQLiteCentralStorageAAP) UpdateAccount(account *azmodels.Account) (*azmodels.Account, error) {
	logger := s.ctx.GetLogger()
	db, err := s.sqliteConnector.Connect(logger, context.Background())
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrServerInfrastructure, "storage: cannot connect to sqlite.")
	}
	return s.upsertAccount(db, false, account)
}

// DeleteAccount deletes an account.
func (s SQLiteCentralStorageAAP) DeleteAccount(accountID int64) (*azmodels.Account, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// GetAllAccounts returns all accounts.
func (s SQLiteCentralStorageAAP) GetAllAccounts(fields map[string]any) ([]azmodels.Account, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}
