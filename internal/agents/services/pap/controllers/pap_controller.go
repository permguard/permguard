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
	"fmt"
	"strings"

	notppkts "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	statemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	smpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/transport/models/pap"
	"go.uber.org/zap"
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
	var logger *zap.Logger; if s.ctx != nil { logger = s.ctx.Logger() }

	if ledger == nil {
		return nil, fmt.Errorf("pap-controller: ledger is nil")
	}
	if ledger.ZoneID <= 0 {
		return nil, fmt.Errorf("pap-controller: invalid zone id %d", ledger.ZoneID)
	}
	if strings.TrimSpace(ledger.Name) == "" {
		return nil, fmt.Errorf("pap-controller: ledger name is empty")
	}

	if logger != nil {
		logger.Info("creating ledger", zap.Int64("zone_id", ledger.ZoneID), zap.String("name", ledger.Name))
	}

	result, err := s.storage.CreateLedger(ctx, ledger)
	if err != nil {
		if logger != nil {
			logger.Error("failed to create ledger", zap.Int64("zone_id", ledger.ZoneID), zap.Error(err))
		}
		return nil, fmt.Errorf("pap-controller: %w", err)
	}

	return result, nil
}

// UpdateLedger updates a ledger.
func (s PAPController) UpdateLedger(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error) {
	var logger *zap.Logger; if s.ctx != nil { logger = s.ctx.Logger() }

	if ledger == nil {
		return nil, fmt.Errorf("pap-controller: ledger is nil")
	}
	if ledger.ZoneID <= 0 {
		return nil, fmt.Errorf("pap-controller: invalid zone id %d", ledger.ZoneID)
	}

	if logger != nil {
		logger.Info("updating ledger", zap.Int64("zone_id", ledger.ZoneID), zap.String("ledger_id", ledger.LedgerID))
	}

	result, err := s.storage.UpdateLedger(ctx, ledger)
	if err != nil {
		if logger != nil {
			logger.Error("failed to update ledger", zap.Int64("zone_id", ledger.ZoneID), zap.Error(err))
		}
		return nil, fmt.Errorf("pap-controller: %w", err)
	}

	return result, nil
}

// DeleteLedger deletes a ledger.
func (s PAPController) DeleteLedger(ctx context.Context, zoneID int64, ledgerID string) (*pap.Ledger, error) {
	var logger *zap.Logger; if s.ctx != nil { logger = s.ctx.Logger() }

	if zoneID <= 0 {
		return nil, fmt.Errorf("pap-controller: invalid zone id %d", zoneID)
	}
	if strings.TrimSpace(ledgerID) == "" {
		return nil, fmt.Errorf("pap-controller: ledger id is empty")
	}

	if logger != nil {
		logger.Info("deleting ledger", zap.Int64("zone_id", zoneID), zap.String("ledger_id", ledgerID))
	}

	result, err := s.storage.DeleteLedger(ctx, zoneID, ledgerID)
	if err != nil {
		if logger != nil {
			logger.Error("failed to delete ledger", zap.Int64("zone_id", zoneID), zap.Error(err))
		}
		return nil, fmt.Errorf("pap-controller: %w", err)
	}

	return result, nil
}

// FetchLedgers gets all ledgers.
func (s PAPController) FetchLedgers(ctx context.Context, page int32, pageSize int32, zoneID int64, fields map[string]any) ([]pap.Ledger, error) {
	var logger *zap.Logger; if s.ctx != nil { logger = s.ctx.Logger() }

	if logger != nil {
		logger.Info("fetching ledgers", zap.Int64("zone_id", zoneID), zap.Int32("page", page), zap.Int32("page_size", pageSize))
	}

	result, err := s.storage.FetchLedgers(ctx, page, pageSize, zoneID, fields)
	if err != nil {
		if logger != nil {
			logger.Error("failed to fetch ledgers", zap.Int64("zone_id", zoneID), zap.Error(err))
		}
		return nil, fmt.Errorf("pap-controller: %w", err)
	}

	return result, nil
}

// OnPullHandleRequestCurrentState handles the request for the current state.
func (s PAPController) OnPullHandleRequestCurrentState(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleRequestCurrentState(handlerCtx, statePacket, packets)
}

// OnPullSendNotifyCurrentStateResponse notifies the current state.
func (s PAPController) OnPullSendNotifyCurrentStateResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPullSendNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
}

// OnPullSendNegotiationRequest sends the negotiation request.
func (s PAPController) OnPullSendNegotiationRequest(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPullSendNegotiationRequest(handlerCtx, statePacket, packets)
}

// OnPullHandleNegotiationResponse handles the negotiation response.
func (s PAPController) OnPullHandleNegotiationResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleNegotiationResponse(handlerCtx, statePacket, packets)
}

// OnPullHandleExchangeDataStream exchanges the data stream.
func (s PAPController) OnPullHandleExchangeDataStream(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleExchangeDataStream(handlerCtx, statePacket, packets)
}

// OnPullHandleCommit handles the commit.
func (s PAPController) OnPullHandleCommit(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPullHandleCommit(handlerCtx, statePacket, packets)
}

// OnPushHandleNotifyCurrentState notifies the current state.
func (s PAPController) OnPushHandleNotifyCurrentState(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPushHandleNotifyCurrentState(handlerCtx, statePacket, packets)
}

// OnPushSendNotifyCurrentStateResponse handles the current state response.
func (s PAPController) OnPushSendNotifyCurrentStateResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPushSendNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
}

// OnPushSendNegotiationRequest handles the negotiation request.
func (s PAPController) OnPushSendNegotiationRequest(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPushSendNegotiationRequest(handlerCtx, statePacket, packets)
}

// OnPushHandleNegotiationResponse sends the negotiation response.
func (s PAPController) OnPushHandleNegotiationResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPushHandleNegotiationResponse(handlerCtx, statePacket, packets)
}

// OnPushHandleExchangeDataStream exchanges the data stream.
func (s PAPController) OnPushHandleExchangeDataStream(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPushHandleExchangeDataStream(handlerCtx, statePacket, packets)
}

// OnPushSendCommit sends the commit.
func (s PAPController) OnPushSendCommit(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return s.storage.OnPushSendCommit(handlerCtx, statePacket, packets)
}
