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
	"fmt"

	aziclients "github.com/permguard/permguard/internal/agents/clients"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/core/errors"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
)

// RemoteServerManager implements the internal manager for the remote file.
type RemoteServerManager struct {
	ctx *aziclicommon.CliCommandContext
}

// NewRemoteServerManager creates a new remoteuration manager.
func NewRemoteServerManager(ctx *aziclicommon.CliCommandContext) (*RemoteServerManager, error) {
	return &RemoteServerManager{
		ctx: ctx,
	}, nil
}

// GetServerRemoteRepo gets the remote repo from the server.
func (m *RemoteServerManager) GetServerRemoteRepo(accountID int64, repo string, server string, aapPort int, papPort int) (*azmodels.Repository, error) {
	appServer := fmt.Sprintf("%s:%d", server, aapPort)
	aapClient, err := aziclients.NewGrpcAAPClient(appServer)
	if err != nil {
		return nil, err
	}
	pppServer := fmt.Sprintf("%s:%d", server, papPort)
	papClient, err := aziclients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return nil, err
	}
	srvAccounts, err := aapClient.FetchAccountsByID(1, 1, accountID)
	if err != nil || srvAccounts == nil || len(srvAccounts) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: account %d does not exist", accountID))
	}
	srvRepo, err := papClient.FetchRepositoriesByName(1, 1, accountID, repo)
	if err != nil || srvRepo == nil || len(srvRepo) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: repo %s does not exist", repo))
	}
	return &srvRepo[0], nil
}

// NOTPClient is the interface for the NOTP client.
type NOTPClient interface {
	OnPushSendNotifyCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error)
	OnPushHandleNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error)
	OnPushHandleNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error)
	OnPushSendNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error)
	OnPushExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error)
}

// NOTPPush push objects using the NOTP protocol.
func (m *RemoteServerManager) NOTPPush(server string, papPort int, accountID int64, repositoryID string, bag map[string]any, clientProvider NOTPClient) error {
	pppServer := fmt.Sprintf("%s:%d", server, papPort)
	papClient, err := aziclients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return err
	}
	var hostHandler notpstatemachines.HostHandler = func(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
		switch handlerCtx.GetCurrentStateID() {
		case notpstatemachines.NotifyObjectsStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.NotifyCurrentObjectStatesMessage:
				return clientProvider.OnPushSendNotifyCurrentState(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondCurrentStateMessage:
				return clientProvider.OnPushHandleNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
			default:
				return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid message code %d", statePacket.MessageCode))
			}

		case notpstatemachines.PublisherNegotiationStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.NegotiationRequestMessage:
				return clientProvider.OnPushHandleNegotiationRequest(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondNegotiationRequestMessage:
				return clientProvider.OnPushSendNegotiationResponse(handlerCtx, statePacket, packets)
			default:
				return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid message code %d", statePacket.MessageCode))
			}

		case notpstatemachines.PublisherDataStreamStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.ExchangeDataStreamMessage:
				return clientProvider.OnPushExchangeDataStream(handlerCtx, statePacket, packets)
			default:
				return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid message code %d", statePacket.MessageCode))
			}
		default:
			return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid state %d", handlerCtx.GetCurrentStateID()))
		}
	}
	err = papClient.NOTPStream(hostHandler, accountID, repositoryID, bag, notpstatemachines.PushFlowType)
	if err != nil {
		return err
	}
	return nil
}
