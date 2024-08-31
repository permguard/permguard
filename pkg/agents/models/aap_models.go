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

package models

import (
	"time"
)

const (
	FieldAccountAccountID               = "account_id"
	FieldAccountName                    = "name"
	FieldTenantAccountID                = "account_id"
	FieldTenantTenantID                 = "tenant_id"
	FieldTenantName                     = "name"
	FieldIdentitySourceAccountID        = "account_id"
	FieldIdentitySourceName             = "name"
	FieldIdentitySourceIdentitySourceID = "identity_source_id"
	FieldIdentityAccountID              = "account_id"
	FieldIdentityIdentitySourceID       = "identity_source_id"
	FieldIdentityIdentityID             = "identity_id"
	FieldIdentityName                   = "name"
	FieldIdentityKind                   = "kind"
)

// Account is the account.
type Account struct {
	AccountID int64     `json:"account_id" validate:"required,gt=0"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
	UpdatedAt time.Time `json:"updated_at" validate:"required"`
	Name      string    `json:"name" validate:"required,name"`
	RefsHead  string    `json:"refs_head"`
}

// Tenant is the tenant.
type Tenant struct {
	TenantID  string    `json:"tenant_id" validate:"required,isuuid"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
	UpdatedAt time.Time `json:"updated_at" validate:"required"`
	AccountID int64     `json:"account_id" validate:"required,gt=0"`
	Name      string    `json:"name"`
}

// IdentitySource represent and identity source
type IdentitySource struct {
	IdentitySourceID string    `json:"identity_source_id" validate:"required,isuuid"`
	CreatedAt        time.Time `json:"created_at" validate:"required"`
	UpdatedAt        time.Time `json:"updated_at" validate:"required"`
	AccountID        int64     `json:"account_id" validate:"required,gt=0"`
	Name             string    `json:"name" validate:"required"`
}

// Identity is the entity representing the user or role
type Identity struct {
	IdentityID       string    `json:"identity_id" validate:"required,isuuid"`
	CreatedAt        time.Time `json:"created_at" validate:"required"`
	UpdatedAt        time.Time `json:"updated_at" validate:"required"`
	AccountID        int64     `json:"account_id" validate:"required,gt=0"`
	IdentitySourceID string    `json:"identity_source_id" validate:"required,isuuid"`
	Kind             string    `json:"identity_type" validate:"required,oneof='user' 'role'"`
	Name             string    `json:"name" validate:"required"`
}
