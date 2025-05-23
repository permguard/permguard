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
	"errors"
	"fmt"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/internal/transport/clients"
	"github.com/permguard/permguard/pkg/transport/models/pap"

	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
)

// RemoteServerManager implements the internal manager for the remote file.
type RemoteServerManager struct {
	ctx *common.CliCommandContext
}

// NewRemoteServerManager creates a new remoteuration manager.
func NewRemoteServerManager(ctx *common.CliCommandContext) (*RemoteServerManager, error) {
	return &RemoteServerManager{
		ctx: ctx,
	}, nil
}

// GetServerRemoteLedger gets the remote ledger from the server.
func (m *RemoteServerManager) GetServerRemoteLedger(remoteInfo *wkscommon.RemoteInfo, ledgerInfo *wkscommon.LedgerInfo) (*pap.Ledger, error) {
	if remoteInfo == nil {
		return nil, errors.New("cli: remote info is nil")
	}
	if ledgerInfo == nil {
		return nil, errors.New("cli: ledger info is nil")
	}
	zoneerver := fmt.Sprintf("%s:%d", remoteInfo.GetServer(), remoteInfo.GetZAPPort())
	zapClient, err := clients.NewGrpcZAPClient(zoneerver)
	if err != nil {
		return nil, err
	}
	pppServer := fmt.Sprintf("%s:%d", remoteInfo.GetServer(), remoteInfo.GetPAPPort())
	papClient, err := clients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return nil, err
	}
	zoneID := ledgerInfo.GetZoneID()
	ledger := ledgerInfo.GetLedger()
	srvZones, err := zapClient.FetchZonesByID(1, 1, zoneID)
	if err != nil || srvZones == nil || len(srvZones) == 0 {
		return nil, errors.Join(err, fmt.Errorf("cli: zone %d does not exist", zoneID))
	}
	srvLedger, err := papClient.FetchLedgersByName(1, 1, zoneID, ledger)
	if err != nil || srvLedger == nil || len(srvLedger) == 0 {
		return nil, errors.Join(err, fmt.Errorf("cli: ledger %s does not exist", ledger))
	}
	if srvLedger[0].Name != ledger {
		return nil, fmt.Errorf("cli: ledger %s not found", ledger)
	}
	return &srvLedger[0], nil
}

// NOTPClient is the interface for the NOTP client.
type NOTPClient interface {
	OnPushSendNotifyCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPushHandleNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPushHandleNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPushSendNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPushExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPushHandleCommitResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)

	OnPullSendRequestCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPullHandleRequestCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPullSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPullHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPullHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	OnPullSendCommit(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
}

// NOTPPush push objects using the NOTP protocol.
func (m *RemoteServerManager) NOTPPush(server string, papPort int, zoneID int64, ledgerID string, bag map[string]any, clientProvider NOTPClient) (*notpstatemachines.StateMachineRuntimeContext, error) {
	pppServer := fmt.Sprintf("%s:%d", server, papPort)
	papClient, err := clients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return nil, err
	}
	var hostHandler notpstatemachines.HostHandler = func(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
		switch handlerCtx.GetCurrentStateID() {
		case notpstatemachines.NotifyObjectsStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.NotifyCurrentObjectStatesMessage:
				return clientProvider.OnPushSendNotifyCurrentState(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondCurrentStateMessage:
				return clientProvider.OnPushHandleNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.PublisherNegotiationStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.NegotiationRequestMessage:
				return clientProvider.OnPushHandleNegotiationRequest(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondNegotiationRequestMessage:
				return clientProvider.OnPushSendNegotiationResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.PublisherDataStreamStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.ExchangeDataStreamMessage:
				return clientProvider.OnPushExchangeDataStream(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.PublisherCommitStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.CommitMessage:
				return clientProvider.OnPushHandleCommitResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}
		default:
			return nil, fmt.Errorf("cli: invalid state %d", handlerCtx.GetCurrentStateID())
		}
	}
	return papClient.NOTPStream(hostHandler, zoneID, ledgerID, bag, notpstatemachines.PushFlowType)
}

// NOTPPull pull objects using the NOTP protocol.
func (m *RemoteServerManager) NOTPPull(server string, papPort int, zoneID int64, ledgerID string, bag map[string]any, clientProvider NOTPClient) (*notpstatemachines.StateMachineRuntimeContext, error) {
	pppServer := fmt.Sprintf("%s:%d", server, papPort)
	papClient, err := clients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return nil, err
	}
	var hostHandler notpstatemachines.HostHandler = func(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
		switch handlerCtx.GetCurrentStateID() {
		case notpstatemachines.RequestObjectsStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.RequestCurrentObjectsStateMessage:
				return clientProvider.OnPullSendRequestCurrentState(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondCurrentStateMessage:
				return clientProvider.OnPullHandleRequestCurrentStateResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.SubscriberNegotiationStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.NegotiationRequestMessage:
				return clientProvider.OnPullSendNegotiationRequest(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondNegotiationRequestMessage:
				return clientProvider.OnPullHandleNegotiationResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.SubscriberDataStreamStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.ExchangeDataStreamMessage:
				return clientProvider.OnPullHandleExchangeDataStream(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.SubscriberCommitStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.CommitMessage:
				return clientProvider.OnPullSendCommit(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("cli: invalid message code %d", statePacket.MessageCode)
			}
		default:
			return nil, fmt.Errorf("cli: invalid state %d", handlerCtx.GetCurrentStateID())
		}
	}
	return papClient.NOTPStream(hostHandler, zoneID, ledgerID, bag, notpstatemachines.PullFlowType)
}
