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

package remoteserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/internal/transport/clients"
	"github.com/permguard/permguard/pkg/transport/models/pap"

	notppkts "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	statemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	smpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
)

// Manager implements the internal manager for the remote file.
type Manager struct {
	ctx *common.CliCommandContext
}

// NewManager creates a new remoteuration manager.
func NewManager(ctx *common.CliCommandContext) (*Manager, error) {
	return &Manager{
		ctx: ctx,
	}, nil
}

// ServerRemoteLedger gets the remote ledger from the server.
func (m *Manager) ServerRemoteLedger(remoteInfo *wkscommon.RemoteInfo, ledgerInfo *wkscommon.LedgerInfo) (*pap.Ledger, error) {
	if remoteInfo == nil {
		return nil, errors.New("cli: remote info is nil")
	}
	if ledgerInfo == nil {
		return nil, errors.New("cli: ledger info is nil")
	}
	zoneerver := fmt.Sprintf("%s:%d", remoteInfo.Server(), remoteInfo.ZAPPort())
	zapClient, err := clients.NewGrpcZAPClient(zoneerver)
	if err != nil {
		return nil, err
	}
	pppServer := fmt.Sprintf("%s:%d", remoteInfo.Server(), remoteInfo.PAPPort())
	papClient, err := clients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return nil, err
	}
	zoneID := ledgerInfo.ZoneID()
	ledger := ledgerInfo.Ledger()
	srvZones, err := zapClient.FetchZonesByID(context.Background(), 1, 1, zoneID)
	if err != nil || srvZones == nil || len(srvZones) == 0 {
		return nil, errors.Join(fmt.Errorf("cli: zone %d does not exist", zoneID), err)
	}
	srvLedger, err := papClient.FetchLedgersByName(context.Background(), 1, 1, zoneID, ledger)
	if err != nil || srvLedger == nil || len(srvLedger) == 0 {
		return nil, errors.Join(fmt.Errorf("cli: ledger %s does not exist", ledger), err)
	}
	if srvLedger[0].Name != ledger {
		return nil, fmt.Errorf("cli: ledger %s not found", ledger)
	}
	return &srvLedger[0], nil
}

// NOTPClient is the interface for the NOTP client.
type NOTPClient interface {
	OnPushSendNotifyCurrentState(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPushHandleNotifyCurrentStateResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPushHandleNegotiationRequest(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPushSendNegotiationResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPushExchangeDataStream(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPushHandleCommitResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)

	OnPullSendRequestCurrentState(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPullHandleRequestCurrentStateResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPullSendNegotiationRequest(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPullHandleNegotiationResponse(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPullHandleExchangeDataStream(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
	OnPullSendCommit(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error)
}

// NOTPPush push objects using the NOTP protocol.
func (m *Manager) NOTPPush(server string, papPort int, zoneID int64, ledgerID string, bag map[string]any, clientProvider NOTPClient) (*statemachines.StateMachineRuntimeContext, error) {
	pppServer := fmt.Sprintf("%s:%d", server, papPort)
	papClient, err := clients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return nil, err
	}
	var hostHandler statemachines.HostHandler = func(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
		switch handlerCtx.CurrentStateID() {
		case statemachines.NotifyObjectsStateID:
			switch statePacket.MessageCode {
			case smpackets.NotifyCurrentObjectStatesMessage:
				return clientProvider.OnPushSendNotifyCurrentState(handlerCtx, statePacket, packets)
			case smpackets.RespondCurrentStateMessage:
				return clientProvider.OnPushHandleNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.PublisherNegotiationStateID:
			switch statePacket.MessageCode {
			case smpackets.NegotiationRequestMessage:
				return clientProvider.OnPushHandleNegotiationRequest(handlerCtx, statePacket, packets)
			case smpackets.RespondNegotiationRequestMessage:
				return clientProvider.OnPushSendNegotiationResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.PublisherDataStreamStateID:
			switch statePacket.MessageCode {
			case smpackets.ExchangeDataStreamMessage:
				return clientProvider.OnPushExchangeDataStream(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.PublisherCommitStateID:
			switch statePacket.MessageCode {
			case smpackets.CommitMessage:
				return clientProvider.OnPushHandleCommitResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}
		default:
			return nil, fmt.Errorf("cli: invalid state %d", handlerCtx.CurrentStateID())
		}
	}
	return papClient.NOTPStream(hostHandler, zoneID, ledgerID, bag, statemachines.PushFlowType)
}

// NOTPPull pull objects using the NOTP protocol.
func (m *Manager) NOTPPull(server string, papPort int, zoneID int64, ledgerID string, bag map[string]any, clientProvider NOTPClient) (*statemachines.StateMachineRuntimeContext, error) {
	pppServer := fmt.Sprintf("%s:%d", server, papPort)
	papClient, err := clients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return nil, err
	}
	var hostHandler statemachines.HostHandler = func(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
		switch handlerCtx.CurrentStateID() {
		case statemachines.RequestObjectsStateID:
			switch statePacket.MessageCode {
			case smpackets.RequestCurrentObjectsStateMessage:
				return clientProvider.OnPullSendRequestCurrentState(handlerCtx, statePacket, packets)
			case smpackets.RespondCurrentStateMessage:
				return clientProvider.OnPullHandleRequestCurrentStateResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.SubscriberNegotiationStateID:
			switch statePacket.MessageCode {
			case smpackets.NegotiationRequestMessage:
				return clientProvider.OnPullSendNegotiationRequest(handlerCtx, statePacket, packets)
			case smpackets.RespondNegotiationRequestMessage:
				return clientProvider.OnPullHandleNegotiationResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.SubscriberDataStreamStateID:
			switch statePacket.MessageCode {
			case smpackets.ExchangeDataStreamMessage:
				return clientProvider.OnPullHandleExchangeDataStream(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.SubscriberCommitStateID:
			switch statePacket.MessageCode {
			case smpackets.CommitMessage:
				return clientProvider.OnPullSendCommit(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}
		default:
			return nil, fmt.Errorf("cli: invalid state %d", handlerCtx.CurrentStateID())
		}
	}
	return papClient.NOTPStream(hostHandler, zoneID, ledgerID, bag, statemachines.PullFlowType)
}
