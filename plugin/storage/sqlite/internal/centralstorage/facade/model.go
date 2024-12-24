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

package facade

import (
	"fmt"
	"time"
)

// Application is the model for the application table.
type Application struct {
	ApplicationID int64     `db:"application_id"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
	Name          string    `db:"name"`
}

// LogApplicationEntry returns a string representation of the application.
func LogApplicationEntry(application *Application) string {
	if application == nil {
		return "application is nil"
	}
	return fmt.Sprintf("accound id: %d, name: %s", application.ApplicationID, application.Name)
}

// IdentitySource is the model for the identity_source table.
type IdentitySource struct {
	IdentitySourceID string    `db:"identity_source_id"`
	CreatedAt        time.Time `db:"created_at"`
	UpdatedAt        time.Time `db:"updated_at"`
	ApplicationID    int64     `db:"application_id"`
	Name             string    `db:"name"`
}

// LogIdentitySourceEntry  returns a string representation of the identity source.
func LogIdentitySourceEntry(identitySource *IdentitySource) string {
	if identitySource == nil {
		return "identity source is nil"
	}
	return fmt.Sprintf("identity source id: %s, application id: %d, name: %s", identitySource.IdentitySourceID, identitySource.ApplicationID, identitySource.Name)
}

// Identity is the model for the identity table.
type Identity struct {
	IdentityID       string    `db:"identity_id"`
	CreatedAt        time.Time `db:"created_at"`
	UpdatedAt        time.Time `db:"updated_at"`
	ApplicationID    int64     `db:"application_id"`
	IdentitySourceID string    `db:"identity_source_id"`
	Kind             int16     `db:"kind"`
	Name             string    `db:"name"`
}

// LogIdentityEntry returns a string representation of the identity.
func LogIdentityEntry(identity *Identity) string {
	if identity == nil {
		return "identity is nil"
	}
	return fmt.Sprintf("identity id: %s, identity source id %s, application id: %d, name: %s", identity.IdentityID, identity.IdentitySourceID, identity.ApplicationID, identity.Name)
}

// Tenant is the model for the tenant table.
type Tenant struct {
	TenantID      string    `db:"tenant_id"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
	ApplicationID int64     `db:"application_id"`
	Name          string    `db:"name"`
}

// LogTenantEntry returns a string representation of the tenant.
func LogTenantEntry(tenant *Tenant) string {
	if tenant == nil {
		return "tenant is nil"
	}
	return fmt.Sprintf("tenant id: %s, application id: %d, name: %s", tenant.TenantID, tenant.ApplicationID, tenant.Name)
}

// Ledger is the model for the schema table.
type Ledger struct {
	LedgerID      string    `db:"ledger_id"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
	ApplicationID int64     `db:"application_id"`
	Name          string    `db:"name"`
	Ref           string    `db:"ref"`
}

// LogLedgerEntry returns a string representation of the ledger.
func LogLedgerEntry(ledger *Ledger) string {
	if ledger == nil {
		return "tenant is nil"
	}
	return fmt.Sprintf("ledger id: %s, application id: %d, name: %s", ledger.LedgerID, ledger.ApplicationID, ledger.Name)
}

// KeyValue is the model for the key_value table.
type KeyValue struct {
	Key   string `db:"kv_key"`
	Value []byte `db:"kv_value"`
}

// LogKeyValueEntry returns a string representation of the key value.
func LogKeyValueEntry(keyValue *KeyValue) string {
	if keyValue == nil {
		return "keyvalue is nil"
	}
	return fmt.Sprintf("keyvalue key: %s", keyValue.Key)
}
