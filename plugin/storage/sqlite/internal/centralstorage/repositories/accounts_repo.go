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

package repositories

import (
	"fmt"

	"gorm.io/gorm"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azivalidators "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/validators"
)

// UpsertAccount creates or updates an account.
func UpsertAccount(db *gorm.DB, isCreate bool, account *azmodels.Account) (*azmodels.Account, error) {
	if account == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrInvalidInputParameter, "storage: account is nil.")
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
			return nil, fmt.Errorf("storage: account cannot be created. %w", azerrors.ErrStorageGeneric)
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
			return nil, fmt.Errorf("storage: account cannot be updated. %w", azerrors.ErrStorageGeneric)
		}
	}
	return mapAccountToAgentAccount(&dbAccount)
}
