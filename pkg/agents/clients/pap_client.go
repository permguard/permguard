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

package clients

import (
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// GrpcPAPClient is the gRPC PAP client servicer.
type GrpcPAPClient interface {
	// CreateLedger creates a ledger.
	CreateLedger(applicationID int64, kind string, name string) (*azmodels.Ledger, error)
	// UpdateLedger updates a ledger.
	UpdateLedger(ledger *azmodels.Ledger) (*azmodels.Ledger, error)
	// DeleteLedger deletes a ledger.
	DeleteLedger(applicationID int64, ledgerID string) (*azmodels.Ledger, error)
	// FetchLedgers returns all ledgers.
	FetchLedgers(page int32, pageSize int32, applicationID int64) ([]azmodels.Ledger, error)
	// FetchLedgersByID returns all ledgers filtering by ledger id.
	FetchLedgersByID(page int32, pageSize int32, applicationID int64, ledgerID string) ([]azmodels.Ledger, error)
	// FetchLedgersByName returns all ledgers filtering by name.
	FetchLedgersByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodels.Ledger, error)
	// FetchLedgersBy returns all ledgers filtering by ledger id and name.
	FetchLedgersBy(page int32, pageSize int32, applicationID int64, ledgerID string, kind string, name string) ([]azmodels.Ledger, error)
}
