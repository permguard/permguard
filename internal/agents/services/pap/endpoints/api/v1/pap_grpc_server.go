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
	"context"
	"errors"
	"fmt"
	"time"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/transport/models/pap"

	notpsm "github.com/permguard/permguard/internal/transport/notp/statemachines"
	notppkts "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	statemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	smpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
	notpxport "github.com/permguard/permguard/notp-protocol/pkg/notp/transport"
)

const (
	// DefaultTimeout is the default timeout for the wired state machine.
	DefaultTimeout = 30 * time.Second
)

// PAPService is the service for the PAP.
type PAPService interface {
	Setup() error
	// CreateLedger creates a new ledger.
	CreateLedger(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error)
	// UpdateLedger updates an ledger.
	UpdateLedger(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error)
	// DeleteLedger deletes an ledger.
	DeleteLedger(ctx context.Context, zoneID int64, ledgerID string) (*pap.Ledger, error)
	// FetchLedgers gets all ledgers.
	FetchLedgers(ctx context.Context, page int32, pageSize int32, zoneID int64, fields map[string]any) ([]pap.Ledger, error)
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

// NewPAPServer creates a new PAP server.
func NewPAPServer(endpointCtx *services.EndpointContext, service PAPService) (*PAPServer, error) {
	return &PAPServer{
		ctx:     endpointCtx,
		service: service,
	}, nil
}

// PAPServer is the gRPC server for the PAP.
type PAPServer struct {
	UnimplementedV1PAPServiceServer
	ctx     *services.EndpointContext
	service PAPService
}

// CreateLedger creates a new ledger.
func (s *PAPServer) CreateLedger(ctx context.Context, ledgerRequest *LedgerCreateRequest) (*LedgerResponse, error) {
	ledger, err := s.service.CreateLedger(ctx, &pap.Ledger{ZoneID: ledgerRequest.ZoneID, Name: ledgerRequest.Name, Kind: ledgerRequest.Kind})
	if err != nil {
		return nil, err
	}
	return MapAgentLedgerToGrpcLedgerResponse(ledger)
}

// UpdateLedger updates a ledger.
func (s *PAPServer) UpdateLedger(ctx context.Context, ledgerRequest *LedgerUpdateRequest) (*LedgerResponse, error) {
	ledger, err := s.service.UpdateLedger(ctx, &pap.Ledger{LedgerID: ledgerRequest.LedgerID, ZoneID: ledgerRequest.ZoneID, Name: ledgerRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentLedgerToGrpcLedgerResponse(ledger)
}

// DeleteLedger deletes a ledger.
func (s *PAPServer) DeleteLedger(ctx context.Context, ledgerRequest *LedgerDeleteRequest) (*LedgerResponse, error) {
	ledger, err := s.service.DeleteLedger(ctx, ledgerRequest.ZoneID, ledgerRequest.LedgerID)
	if err != nil {
		return nil, err
	}
	return MapAgentLedgerToGrpcLedgerResponse(ledger)
}

// FetchLedgers returns all ledgers.
func (s *PAPServer) FetchLedgers(ledgerRequest *LedgerFetchRequest, stream grpc.ServerStreamingServer[LedgerResponse]) error {
	fields := map[string]any{}
	fields[pap.FieldLedgerZoneID] = ledgerRequest.ZoneID
	if ledgerRequest.Kind != nil {
		fields[pap.FieldLedgerKind] = *ledgerRequest.Kind
	}
	if ledgerRequest.Name != nil {
		fields[pap.FieldLedgerName] = *ledgerRequest.Name
	}
	if ledgerRequest.LedgerID != nil {
		fields[pap.FieldLedgerLedgerID] = *ledgerRequest.LedgerID
	}
	page := int32(0)
	if ledgerRequest.Page != nil {
		page = *ledgerRequest.Page
	}
	pageSize := int32(0)
	if ledgerRequest.PageSize != nil {
		pageSize = *ledgerRequest.PageSize
	}
	ledgers, err := s.service.FetchLedgers(context.TODO(), page, pageSize, ledgerRequest.ZoneID, fields)
	if err != nil {
		return err
	}
	for _, ledger := range ledgers {
		cvtedLedger, err := MapAgentLedgerToGrpcLedgerResponse(&ledger)
		if err != nil {
			return err
		}
		if err := stream.SendMsg(cvtedLedger); err != nil {
			return err
		}
	}
	return nil
}

// ReceivePack receives objects from the client.
func (s *PAPServer) ReceivePack(_ grpc.BidiStreamingServer[PackMessage, PackMessage]) error {
	return nil
}

// createWiredStateMachine creates a wired state machine.
func (s *PAPServer) createWiredStateMachine(stream grpc.BidiStreamingServer[PackMessage, PackMessage]) (*statemachines.StateMachine, error) {
	var sender notpxport.WireSendFunc = func(packet *notppkts.Packet) error {
		pack := &PackMessage{
			Data: packet.Data,
		}
		return stream.Send(pack)
	}
	var receiver notpxport.WireRecvFunc = func() (*notppkts.Packet, error) {
		pack, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		return &notppkts.Packet{Data: pack.Data}, nil
	}
	transportStream, err := notpxport.NewWireStream(sender, receiver, DefaultTimeout)
	if err != nil {
		return nil, err
	}
	transportLayer, err := notpxport.NewTransportLayer(transportStream.TransmitPacket, transportStream.ReceivePacket, nil)
	if err != nil {
		return nil, err
	}
	var hostHandler statemachines.HostHandler = func(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
		switch handlerCtx.CurrentStateID() {
		case statemachines.ProcessRequestObjectsStateID:
			switch statePacket.MessageCode {
			case smpackets.RequestCurrentObjectsStateMessage:
				return s.service.OnPullHandleRequestCurrentState(handlerCtx, statePacket, packets)
			case smpackets.RespondCurrentStateMessage:
				return s.service.OnPullSendNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.PublisherNegotiationStateID:
			switch statePacket.MessageCode {
			case smpackets.NegotiationRequestMessage:
				return s.service.OnPullSendNegotiationRequest(handlerCtx, statePacket, packets)
			case smpackets.RespondNegotiationRequestMessage:
				return s.service.OnPullHandleNegotiationResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.PublisherDataStreamStateID:
			switch statePacket.MessageCode {
			case smpackets.ExchangeDataStreamMessage:
				return s.service.OnPullHandleExchangeDataStream(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.PublisherCommitStateID:
			switch statePacket.MessageCode {
			case smpackets.CommitMessage:
				return s.service.OnPullHandleCommit(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.ProcessNotifyObjectsStateID:
			switch statePacket.MessageCode {
			case smpackets.NotifyCurrentObjectStatesMessage:
				return s.service.OnPushHandleNotifyCurrentState(handlerCtx, statePacket, packets)
			case smpackets.RespondCurrentStateMessage:
				return s.service.OnPushSendNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.SubscriberNegotiationStateID:
			switch statePacket.MessageCode {
			case smpackets.NegotiationRequestMessage:
				return s.service.OnPushSendNegotiationRequest(handlerCtx, statePacket, packets)
			case smpackets.RespondNegotiationRequestMessage:
				return s.service.OnPushHandleNegotiationResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.SubscriberDataStreamStateID:
			switch statePacket.MessageCode {
			case smpackets.ExchangeDataStreamMessage:
				return s.service.OnPushHandleExchangeDataStream(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case statemachines.SubscriberCommitStateID:
			switch statePacket.MessageCode {
			case smpackets.CommitMessage:
				return s.service.OnPushSendCommit(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}
		default:
			return nil, fmt.Errorf("pap-endpoint: invalid state %d", handlerCtx.CurrentStateID())
		}
	}
	stateMachine, err := statemachines.NewLeaderStateMachine(hostHandler, transportLayer)
	if err != nil {
		return nil, err
	}
	return stateMachine, nil
}

// NOTPStream handles bidirectional stream using the NOTP protocol.
func (s *PAPServer) NOTPStream(stream grpc.BidiStreamingServer[PackMessage, PackMessage]) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return errors.New("pap-endpoint: notp stream missing metadata")
	}
	zoneID, ok := md[notpsm.ZoneIDKey]
	if !ok || len(zoneID) == 0 {
		return errors.New("pap-endpoint: notp stream missing zone id")
	}
	repositoryID, ok := md[notpsm.LedgerIDKey]
	if !ok || len(repositoryID) == 0 {
		return errors.New("pap-endpoint: notp stream missing ledger id")
	}

	stateMachine, err := s.createWiredStateMachine(stream)
	if err != nil {
		return err
	}
	bag := map[string]any{}
	bag[notpsm.ZoneIDKey] = zoneID[0]
	bag[notpsm.LedgerIDKey] = repositoryID[0]
	_, err = stateMachine.Run(bag, statemachines.UnknownFlowType)
	if err != nil {
		return errors.Join(errors.New("pap-endpoint: notp stream unhandled err"), err)
	}
	return nil
}
