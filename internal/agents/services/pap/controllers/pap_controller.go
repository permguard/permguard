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

	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
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

// OnPullHandleRequestCurrentState handles the request for the current state.
func (s PAPController) OnPullHandleRequestCurrentState(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleRequestCurrentState(ctx, handlerCtx, statePacket, packets)
}

// OnPullSendNotifyCurrentStateResponse notifies the current state.
func (s PAPController) OnPullSendNotifyCurrentStateResponse(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullSendNotifyCurrentStateResponse(ctx, handlerCtx, statePacket, packets)
}

// OnPullSendNegotiationRequest sends the negotiation request.
func (s PAPController) OnPullSendNegotiationRequest(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullSendNegotiationRequest(ctx, handlerCtx, statePacket, packets)
}

// OnPullHandleNegotiationResponse handles the negotiation response.
func (s PAPController) OnPullHandleNegotiationResponse(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleNegotiationResponse(ctx, handlerCtx, statePacket, packets)
}

// OnPullHandleExchangeDataStream exchanges the data stream.
func (s PAPController) OnPullHandleExchangeDataStream(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleExchangeDataStream(ctx, handlerCtx, statePacket, packets)
}

// OnPullHandleCommit handles the commit.
func (s PAPController) OnPullHandleCommit(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleCommit(ctx, handlerCtx, statePacket, packets)
}

// OnPushHandleNotifyCurrentState notifies the current state.
func (s PAPController) OnPushHandleNotifyCurrentState(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushHandleNotifyCurrentState(ctx, handlerCtx, statePacket, packets)
}

// OnPushSendNotifyCurrentStateResponse handles the current state response.
func (s PAPController) OnPushSendNotifyCurrentStateResponse(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushSendNotifyCurrentStateResponse(ctx, handlerCtx, statePacket, packets)
}

// OnPushSendNegotiationRequest sends the negotiation request.
func (s PAPController) OnPushSendNegotiationRequest(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushSendNegotiationRequest(ctx, handlerCtx, statePacket, packets)
}

// OnPushHandleNegotiationResponse sends the negotiation response.
func (s PAPController) OnPushHandleNegotiationResponse(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushHandleNegotiationResponse(ctx, handlerCtx, statePacket, packets)
}

// OnPushHandleExchangeDataStream exchanges the data stream.
func (s PAPController) OnPushHandleExchangeDataStream(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushHandleExchangeDataStream(ctx, handlerCtx, statePacket, packets)
}

// OnPushSendCommit sends the commit.
func (s PAPController) OnPushSendCommit(ctx context.Context, handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushSendCommit(ctx, handlerCtx, statePacket, packets)
}
