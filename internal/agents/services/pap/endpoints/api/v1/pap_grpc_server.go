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

	notptransportsm "github.com/permguard/permguard/internal/transport/notp/statemachines"
	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
	notptransport "github.com/permguard/permguard/notp-protocol/pkg/notp/transport"
)

const (
	// DefaultTimeout is the default timeout for the wired state machine.
	DefaultTimeout = 30 * time.Second
)

// PAPService is the service for the PAP.
type PAPService interface {
	Setup() error
	// CreateLedger creates a new ledger.
	CreateLedger(ledger *pap.Ledger) (*pap.Ledger, error)
	// UpdateLedger updates an ledger.
	UpdateLedger(ledger *pap.Ledger) (*pap.Ledger, error)
	// DeleteLedger deletes an ledger.
	DeleteLedger(zoneID int64, ledgerID string) (*pap.Ledger, error)
	// FetchLedgers gets all ledgers.
	FetchLedgers(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]pap.Ledger, error)
	// OnPullHandleRequestCurrentState handles the request for the current state.
	OnPullHandleRequestCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPullSendNotifyCurrentStateResponse notifies the current state.
	OnPullSendNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPullSendNegotiationRequest sends the negotiation request.
	OnPullSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPullHandleNegotiationResponse handles the negotiation response.
	OnPullHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPullHandleExchangeDataStream exchanges the data stream.
	OnPullHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPullHandleCommit handles the commit.
	OnPullHandleCommit(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPushHandleNotifyCurrentState notifies the current state.
	OnPushHandleNotifyCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPushSendNotifyCurrentStateResponse handles the current state response.
	OnPushSendNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPushSendNegotiationRequest sends the negotiation request.
	OnPushSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPushHandleNegotiationResponse handles the negotiation response.
	OnPushHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPushHandleExchangeDataStream exchanges the data stream.
	OnPushHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
	// OnPushSendCommit sends the commit.
	OnPushSendCommit(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error)
}

// NewV1PAPServer creates a new PAP server.
func NewV1PAPServer(endpointCtx *services.EndpointContext, Service PAPService) (*V1PAPServer, error) {
	return &V1PAPServer{
		ctx:     endpointCtx,
		service: Service,
	}, nil
}

// V1PAPServer is the gRPC server for the PAP.
type V1PAPServer struct {
	UnimplementedV1PAPServiceServer
	ctx     *services.EndpointContext
	service PAPService
}

// CreateLedger creates a new ledger.
func (s *V1PAPServer) CreateLedger(ctx context.Context, ledgerRequest *LedgerCreateRequest) (*LedgerResponse, error) {
	ledger, err := s.service.CreateLedger(&pap.Ledger{ZoneID: ledgerRequest.ZoneID, Name: ledgerRequest.Name, Kind: ledgerRequest.Kind})
	if err != nil {
		return nil, err
	}
	return MapAgentLedgerToGrpcLedgerResponse(ledger)
}

// UpdateLedger updates a ledger.
func (s *V1PAPServer) UpdateLedger(ctx context.Context, ledgerRequest *LedgerUpdateRequest) (*LedgerResponse, error) {
	ledger, err := s.service.UpdateLedger((&pap.Ledger{LedgerID: ledgerRequest.LedgerID, ZoneID: ledgerRequest.ZoneID, Name: ledgerRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentLedgerToGrpcLedgerResponse(ledger)
}

// DeleteLedger deletes a ledger.
func (s *V1PAPServer) DeleteLedger(ctx context.Context, ledgerRequest *LedgerDeleteRequest) (*LedgerResponse, error) {
	ledger, err := s.service.DeleteLedger(ledgerRequest.ZoneID, ledgerRequest.LedgerID)
	if err != nil {
		return nil, err
	}
	return MapAgentLedgerToGrpcLedgerResponse(ledger)
}

// FetchLedgers returns all ledgers.
func (s *V1PAPServer) FetchLedgers(ledgerRequest *LedgerFetchRequest, stream grpc.ServerStreamingServer[LedgerResponse]) error {
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
		page = int32(*ledgerRequest.Page)
	}
	pageSize := int32(0)
	if ledgerRequest.PageSize != nil {
		pageSize = int32(*ledgerRequest.PageSize)
	}
	ledgers, err := s.service.FetchLedgers(page, pageSize, ledgerRequest.ZoneID, fields)
	if err != nil {
		return err
	}
	for _, ledger := range ledgers {
		cvtedLedger, err := MapAgentLedgerToGrpcLedgerResponse(&ledger)
		if err != nil {
			return err
		}
		stream.SendMsg(cvtedLedger)
	}
	return nil
}

// ReceivePack receives objects from the client.
func (s *V1PAPServer) ReceivePack(stream grpc.BidiStreamingServer[PackMessage, PackMessage]) error {
	return nil
}

// createWiredStateMachine creates a wired state machine.
func (s *V1PAPServer) createWiredStateMachine(stream grpc.BidiStreamingServer[PackMessage, PackMessage]) (*notpstatemachines.StateMachine, error) {
	var sender notptransport.WireSendFunc = func(packet *notppackets.Packet) error {
		pack := &PackMessage{
			Data: packet.Data,
		}
		return stream.Send(pack)
	}
	var receiver notptransport.WireRecvFunc = func() (*notppackets.Packet, error) {
		pack, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		return &notppackets.Packet{Data: pack.Data}, nil
	}
	transportStream, err := notptransport.NewWireStream(sender, receiver, DefaultTimeout)
	if err != nil {
		return nil, err
	}
	transportLayer, err := notptransport.NewTransportLayer(transportStream.TransmitPacket, transportStream.ReceivePacket, nil)
	if err != nil {
		return nil, err
	}
	var hostHandler notpstatemachines.HostHandler = func(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
		switch handlerCtx.CurrentStateID() {
		case notpstatemachines.ProcessRequestObjectsStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.RequestCurrentObjectsStateMessage:
				return s.service.OnPullHandleRequestCurrentState(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondCurrentStateMessage:
				return s.service.OnPullSendNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.PublisherNegotiationStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.NegotiationRequestMessage:
				return s.service.OnPullSendNegotiationRequest(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondNegotiationRequestMessage:
				return s.service.OnPullHandleNegotiationResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.PublisherDataStreamStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.ExchangeDataStreamMessage:
				return s.service.OnPullHandleExchangeDataStream(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.PublisherCommitStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.CommitMessage:
				return s.service.OnPullHandleCommit(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.ProcessNotifyObjectsStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.NotifyCurrentObjectStatesMessage:
				return s.service.OnPushHandleNotifyCurrentState(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondCurrentStateMessage:
				return s.service.OnPushSendNotifyCurrentStateResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.SubscriberNegotiationStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.NegotiationRequestMessage:
				return s.service.OnPushSendNegotiationRequest(handlerCtx, statePacket, packets)
			case notpsmpackets.RespondNegotiationRequestMessage:
				return s.service.OnPushHandleNegotiationResponse(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.SubscriberDataStreamStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.ExchangeDataStreamMessage:
				return s.service.OnPushHandleExchangeDataStream(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}

		case notpstatemachines.SubscriberCommitStateID:
			switch statePacket.MessageCode {
			case notpsmpackets.CommitMessage:
				return s.service.OnPushSendCommit(handlerCtx, statePacket, packets)
			default:
				return nil, fmt.Errorf("pap-endpoint: invalid message code %d", statePacket.MessageCode)
			}
		default:
			return nil, fmt.Errorf("pap-endpoint: invalid state %d", handlerCtx.CurrentStateID())
		}
	}
	stateMachine, err := notpstatemachines.NewLeaderStateMachine(hostHandler, transportLayer)
	if err != nil {
		return nil, err
	}
	return stateMachine, nil
}

// NOTPStream handles bidirectional stream using the NOTP protocol.
func (s *V1PAPServer) NOTPStream(stream grpc.BidiStreamingServer[PackMessage, PackMessage]) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return errors.New("pap-endpoint: notp stream missing metadata")
	}
	zoneID, ok := md[notptransportsm.ZoneIDKey]
	if !ok || len(zoneID) == 0 {
		return errors.New("pap-endpoint: notp stream missing zone id")

	}
	respositoryID, ok := md[notptransportsm.LedgerIDKey]
	if !ok || len(respositoryID) == 0 {
		return errors.New("pap-endpoint: notp stream missing ledger id")
	}

	stateMachine, err := s.createWiredStateMachine(stream)
	if err != nil {
		return err
	}
	bag := map[string]any{}
	bag[notptransportsm.ZoneIDKey] = zoneID[0]
	bag[notptransportsm.LedgerIDKey] = respositoryID[0]
	_, err = stateMachine.Run(bag, notpstatemachines.UnknownFlowType)
	if err != nil {
		return errors.Join(err, errors.New("pap-endpoint: notp stream unhandled err"))
	}
	return nil
}
