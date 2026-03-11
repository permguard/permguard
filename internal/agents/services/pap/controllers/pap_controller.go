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

package controllers

import (
	"context"

	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

// PAPController is the controller for the PAP service.
type PAPController struct {
	ctx     *services.ServiceContext
	storage storage.PAPCentralStorage
}

// Setup initializes the service.
func (s PAPController) Setup() error {
	return nil
}

// NewPAPController creates a new PAP controller.
func NewPAPController(serviceContext *services.ServiceContext, storage storage.PAPCentralStorage) (*PAPController, error) {
	service := PAPController{
		ctx:     serviceContext,
		storage: storage,
	}
	return &service, nil
}

// CreateLedger creates a new ledger.
func (s PAPController) CreateLedger(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error) {
	return s.storage.CreateLedger(ctx, ledger)
}

// UpdateLedger updates an ledger.
func (s PAPController) UpdateLedger(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error) {
	return s.storage.UpdateLedger(ctx, ledger)
}

// DeleteLedger deletes an ledger.
func (s PAPController) DeleteLedger(ctx context.Context, zoneID int64, ledgerID string) (*pap.Ledger, error) {
	return s.storage.DeleteLedger(ctx, zoneID, ledgerID)
}

// FetchLedgers gets all ledgers.
func (s PAPController) FetchLedgers(ctx context.Context, page int32, pageSize int32, zoneID int64, fields map[string]any) ([]pap.Ledger, error) {
	return s.storage.FetchLedgers(ctx, page, pageSize, zoneID, fields)
}

// PushAdvertise handles the push advertise step.
func (s PAPController) PushAdvertise(ctx context.Context, req *pap.PushAdvertiseRequest) (*pap.PushAdvertiseResponse, error) {
	return s.storage.PushAdvertise(ctx, req)
}

// PushTransfer handles the push transfer step.
func (s PAPController) PushTransfer(ctx context.Context, req *pap.PushTransferRequest) (*pap.PushTransferResponse, error) {
	return s.storage.PushTransfer(ctx, req)
}

// PullState handles the pull state step.
func (s PAPController) PullState(ctx context.Context, req *pap.PullStateRequest) (*pap.PullStateResponse, error) {
	return s.storage.PullState(ctx, req)
}

// PullNegotiate handles the pull negotiate step.
func (s PAPController) PullNegotiate(ctx context.Context, req *pap.PullNegotiateRequest) (*pap.PullNegotiateResponse, error) {
	return s.storage.PullNegotiate(ctx, req)
}

// PullObjects handles the pull objects step.
func (s PAPController) PullObjects(ctx context.Context, req *pap.PullObjectsRequest) (*pap.PullObjectsResponse, error) {
	return s.storage.PullObjects(ctx, req)
}
