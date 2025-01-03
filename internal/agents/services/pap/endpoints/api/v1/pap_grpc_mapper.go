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

package v1

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	azmodelspap "github.com/permguard/permguard/pkg/transport/models/pap"
)

func MapGrpcLedgerResponseToAgentLedger(ledger *LedgerResponse) (*azmodelspap.Ledger, error) {
	return &azmodelspap.Ledger{
		LedgerID:      ledger.LedgerID,
		CreatedAt:     ledger.CreatedAt.AsTime(),
		UpdatedAt:     ledger.UpdatedAt.AsTime(),
		ApplicationID: ledger.ApplicationID,
		Kind:          ledger.Kind,
		Name:          ledger.Name,
		Ref:           ledger.Ref,
	}, nil
}

// MapAgentLedgerToGrpcLedgerResponse maps the agent ledger to the gRPC ledger.
func MapAgentLedgerToGrpcLedgerResponse(ledger *azmodelspap.Ledger) (*LedgerResponse, error) {
	return &LedgerResponse{
		LedgerID:      ledger.LedgerID,
		CreatedAt:     timestamppb.New(ledger.CreatedAt),
		UpdatedAt:     timestamppb.New(ledger.UpdatedAt),
		ApplicationID: ledger.ApplicationID,
		Kind:          ledger.Kind,
		Name:          ledger.Name,
		Ref:           ledger.Ref,
	}, nil
}

// MapPointerStringToString maps a pointer string to a string.
func MapPointerStringToString(str *string) string {
	response := ""
	if str != nil {
		response = *str
	}
	return response
}
