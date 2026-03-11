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

package storage

import (
	"context"

	azmpap "github.com/permguard/permguard/pkg/transport/models/pap"
)

// PAPCentralStorage is the interface for the PAP central storage.
type PAPCentralStorage interface {
	// CreateLedger creates a new ledger.
	CreateLedger(ctx context.Context, ledger *azmpap.Ledger) (*azmpap.Ledger, error)
	// UpdateLedger updates an ledger.
	UpdateLedger(ctx context.Context, ledger *azmpap.Ledger) (*azmpap.Ledger, error)
	// DeleteLedger deletes an ledger.
	DeleteLedger(ctx context.Context, zoneID int64, ledgerID string) (*azmpap.Ledger, error)
	// FetchLedgers gets all ledgers.
	FetchLedgers(ctx context.Context, page int32, pageSize int32, zoneID int64, fields map[string]any) ([]azmpap.Ledger, error)
	// PushAdvertise handles the push advertise step.
	PushAdvertise(ctx context.Context, req *azmpap.PushAdvertiseRequest) (*azmpap.PushAdvertiseResponse, error)
	// PushTransfer handles the push transfer step (receives objects and optionally commits).
	PushTransfer(ctx context.Context, req *azmpap.PushTransferRequest) (*azmpap.PushTransferResponse, error)
	// PullState handles the pull state step.
	PullState(ctx context.Context, req *azmpap.PullStateRequest) (*azmpap.PullStateResponse, error)
	// PullNegotiate handles the pull negotiate step (computes diff commit IDs).
	PullNegotiate(ctx context.Context, req *azmpap.PullNegotiateRequest) (*azmpap.PullNegotiateResponse, error)
	// PullObjects handles the pull objects step (returns objects for a commit).
	PullObjects(ctx context.Context, req *azmpap.PullObjectsRequest) (*azmpap.PullObjectsResponse, error)
}
