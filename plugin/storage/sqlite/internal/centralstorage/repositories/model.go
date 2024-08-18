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
	"time"

	"github.com/google/uuid"
)

// Account is the model for the account table.
type Account struct {
	AccountID int64     `db:"account_id"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
	Name      string    `db:"name"`
}

// LogAccountEntry returns a string representation of the account.
func LogAccountEntry(account *Account) string {
	if account == nil {
		return "account is nil"
	}
	return fmt.Sprintf("accound id: %d, name: %s", account.AccountID, account.Name)
}

// IdentitySource is the model for the identity_source table.
type IdentitySource struct {
	IdentitySourceID uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	CreatedAt        time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	AccountID        int64     `gorm:"uniqueIndex:identity_sources_account_id_idx"`
	Name             string    `gorm:"type:varchar(254);uniqueIndex:identity_sources_name_idx"`
}

// Identity is the model for the identity table.
type Identity struct {
	IdentityID       uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	CreatedAt        time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	AccountID        int64     `gorm:"uniqueIndex:identities_account_id_idx"`
	IdentitySourceID uuid.UUID `gorm:"type:uuid;;uniqueIndex:identities_identity_source_id_idx"`
	Kind             int16     `gorm:"default:1"`
	Name             string    `gorm:"type:varchar(254);uniqueIndex:identities_name_idx"`
}

// Tenant is the model for the tenant table.
type Tenant struct {
	TenantID  uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	AccountID int64     `gorm:"uniqueIndex:tenants_account_id_idx"`
	Name      string    `gorm:"type:varchar(254);uniqueIndex:tenants_name_idx"`
}

// Repository is the model for the schema table.
type Repository struct {
	RepositoryID uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	CreatedAt    time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt    time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	AccountID    int64     `gorm:"uniqueIndex:repositories_account_id_idx"`
	Name         string    `gorm:"type:varchar(254);uniqueIndex:repositories_name_idx"`
}
