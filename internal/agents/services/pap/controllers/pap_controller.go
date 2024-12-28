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
	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azStorage "github.com/permguard/permguard/pkg/agents/storage"
	azmodels "github.com/permguard/permguard/pkg/transport/models"
)

type PAPController struct {
	ctx     *azservices.ServiceContext
	storage azStorage.PAPCentralStorage
}

// Setup initializes the service.
func (s PAPController) Setup() error {
	return nil
}

func NewPAPController(serviceContext *azservices.ServiceContext, storage azStorage.PAPCentralStorage) (*PAPController, error) {
	service := PAPController{
		ctx:     serviceContext,
		storage: storage,
	}
	return &service, nil
}

// CreateLedger creates a new ledger.
func (s PAPController) CreateLedger(ledger *azmodels.Ledger) (*azmodels.Ledger, error) {
	return s.storage.CreateLedger(ledger)
}

// UpdateLedger updates an ledger.
func (s PAPController) UpdateLedger(ledger *azmodels.Ledger) (*azmodels.Ledger, error) {
	return s.storage.UpdateLedger(ledger)
}

// DeleteLedger deletes an ledger.
func (s PAPController) DeleteLedger(applicationID int64, ledgerID string) (*azmodels.Ledger, error) {
	return s.storage.DeleteLedger(applicationID, ledgerID)
}

// FetchLedgers gets all ledgers.
func (s PAPController) FetchLedgers(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodels.Ledger, error) {
	return s.storage.FetchLedgers(page, pageSize, applicationID, fields)
}

// OnPullHandleRequestCurrentState handles the request for the current state.
func (s PAPController) OnPullHandleRequestCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleRequestCurrentState(handlerCtx, statePacket, packets)
}

// OnPullSendNotifyCurrentStateResponse notifies the current state.
func (s PAPController) OnPullSendNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullSendNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
}

// OnPullSendNegotiationRequest sends the negotiation request.
func (s PAPController) OnPullSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullSendNegotiationRequest(handlerCtx, statePacket, packets)
}

// OnPullHandleNegotiationResponse handles the negotiation response.
func (s PAPController) OnPullHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleNegotiationResponse(handlerCtx, statePacket, packets)
}

// OnPullHandleExchangeDataStream exchanges the data stream.
func (s PAPController) OnPullHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleExchangeDataStream(handlerCtx, statePacket, packets)
}

// OnPullHandleCommit handles the commit.
func (s PAPController) OnPullHandleCommit(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleCommit(handlerCtx, statePacket, packets)
}

// OnPushHandleNotifyCurrentState notifies the current state.
func (s PAPController) OnPushHandleNotifyCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushHandleNotifyCurrentState(handlerCtx, statePacket, packets)
}

// OnPushSendNotifyCurrentStateResponse handles the current state response.
func (s PAPController) OnPushSendNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushSendNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
}

// OnPushSendNegotiationRequest handles the negotiation request.
func (s PAPController) OnPushSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushSendNegotiationRequest(handlerCtx, statePacket, packets)
}

// OnPushHandleNegotiationResponse sends the negotiation response.
func (s PAPController) OnPushHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushHandleNegotiationResponse(handlerCtx, statePacket, packets)
}

// OnPushHandleExchangeDataStream exchanges the data stream.
func (s PAPController) OnPushHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushHandleExchangeDataStream(handlerCtx, statePacket, packets)
}

// OnPushSendCommit sends the commit.
func (s PAPController) OnPushSendCommit(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	return s.storage.OnPushSendCommit(handlerCtx, statePacket, packets)
}
