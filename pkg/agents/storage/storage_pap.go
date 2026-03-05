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

	notppkts "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	statemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	smpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
	papmodels "github.com/permguard/permguard/pkg/transport/models/pap"
)

// PAPCentralStorage is the interface for the PAP central storage.
type PAPCentralStorage interface {
	// CreateLedger creates a new ledger.
	CreateLedger(ctx context.Context, ledger *papmodels.Ledger) (*papmodels.Ledger, error)
	// UpdateLedger updates a ledger.
	UpdateLedger(ctx context.Context, ledger *papmodels.Ledger) (*papmodels.Ledger, error)
	// DeleteLedger deletes a ledger.
	DeleteLedger(ctx context.Context, zoneID int64, ledgerID string) (*papmodels.Ledger, error)
	// FetchLedgers gets all ledgers.
	FetchLedgers(ctx context.Context, page int32, pageSize int32, zoneID int64, fields map[string]any) ([]papmodels.Ledger, error)
	// OnPullHandleRequestCurrentState handles the request for the current state.
	OnPullHandleRequestCurrentState(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPullSendNotifyCurrentStateResponse notifies the current state.
	OnPullSendNotifyCurrentStateResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPullSendNegotiationRequest sends the negotiation request.
	OnPullSendNegotiationRequest(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPullHandleNegotiationResponse handles the negotiation response.
	OnPullHandleNegotiationResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPullHandleExchangeDataStream exchanges the data stream.
	OnPullHandleExchangeDataStream(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPullHandleCommit handles the commit.
	OnPullHandleCommit(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPushHandleNotifyCurrentState notifies the current state.
	OnPushHandleNotifyCurrentState(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPushSendNotifyCurrentStateResponse handles the current state response.
	OnPushSendNotifyCurrentStateResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPushSendNegotiationRequest sends the negotiation request.
	OnPushSendNegotiationRequest(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPushHandleNegotiationResponse handles the negotiation response.
	OnPushHandleNegotiationResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPushHandleExchangeDataStream exchanges the data stream.
	OnPushHandleExchangeDataStream(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	// OnPushSendCommit sends the commit.
	OnPushSendCommit(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
}
