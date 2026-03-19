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
	"strconv"
	"time"
)

// Zone is the model for the zone table.
type Zone struct {
	ZoneID    int64     `db:"zone_id"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
	Name      string    `db:"name"`
}

// LogZoneEntry returns a string representation of the zone.
func LogZoneEntry(zone *Zone) string {
	if zone == nil {
		return "zone is nil"
	}
	zoneID := "none"
	if zone.ZoneID != 0 {
		zoneID = strconv.FormatInt(zone.ZoneID, 10)
	}
	return fmt.Sprintf("zone id: %s, name: %s", zoneID, zone.Name)
}

// Ledger is the model for the schema table.
type Ledger struct {
	LedgerID  string    `db:"ledger_id"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
	ZoneID    int64     `db:"zone_id"`
	Kind      int16     `db:"kind"`
	Name      string    `db:"name"`
	Ref       string    `db:"ref"`
	TxID      string    `db:"txid"`
}

// LogLedgerEntry returns a string representation of the ledger.
func LogLedgerEntry(ledger *Ledger) string {
	if ledger == nil {
		return "ledger is nil"
	}
	ledgerID := "none"
	if ledger.LedgerID != "" {
		ledgerID = ledger.LedgerID
	}
	zoneID := "none"
	if ledger.ZoneID != 0 {
		zoneID = strconv.FormatInt(ledger.ZoneID, 10)
	}
	return fmt.Sprintf("ledger id: %s, zone id: %s, name: %s", ledgerID, zoneID, ledger.Name)
}

// KeyValue is the model for the key_value table.
type KeyValue struct {
	ZoneID int64  `db:"zone_id"`
	Key    string `db:"kv_key"`
	Value  []byte `db:"kv_value"`
}

// LogKeyValueEntry returns a string representation of the key value.
func LogKeyValueEntry(keyValue *KeyValue) string {
	if keyValue == nil {
		return "keyvalue is nil"
	}
	return fmt.Sprintf("keyvalue key: %s", keyValue.Key)
}

// Transaction is the model for the transactions table.
type Transaction struct {
	TxID      string    `db:"txid"`
	LedgerID  string    `db:"ledger_id"`
	ZoneID    int64     `db:"zone_id"`
	StartedAt time.Time `db:"started_at"`
	Status    string    `db:"status"`
}

// Transaction status constants.
const (
	TxStatusPending   = "pending"
	TxStatusCommitted = "committed"
	TxStatusFailed    = "failed"
)
