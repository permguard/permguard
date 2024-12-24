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
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// mapLedgerToAgentLedger maps a Ledger to a model Ledger.
func mapLedgerToAgentLedger(ledger *azirepos.Ledger) (*azmodels.Ledger, error) {
	kind, err := azirepos.ConvertLedgerKindToString(ledger.Kind)
	if err != nil {
		return nil, err
	}
	return &azmodels.Ledger{
		LedgerID:      ledger.LedgerID,
		CreatedAt:     ledger.CreatedAt,
		UpdatedAt:     ledger.UpdatedAt,
		ApplicationID: ledger.ApplicationID,
		Name:          ledger.Name,
		Kind:          kind,
		Ref:           ledger.Ref,
	}, nil
}
