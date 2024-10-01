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
	"time"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	grpc "google.golang.org/grpc"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
	notptransport "github.com/permguard/permguard-notp-protocol/pkg/notp/transport"
)

const (
	// DefaultTimeout is the default timeout for the wired state machine.
	DefaultTimeout = 30 * time.Second
)

// PAPService is the service for the PAP.
type PAPService interface {
	Setup() error
	// CreateRepository creates a new repository.
	CreateRepository(repository *azmodels.Repository) (*azmodels.Repository, error)
	// UpdateRepository updates an repository.
	UpdateRepository(repository *azmodels.Repository) (*azmodels.Repository, error)
	// DeleteRepository deletes an repository.
	DeleteRepository(accountID int64, repositoryID string) (*azmodels.Repository, error)
	// FetchRepositories gets all repositories.
	FetchRepositories(page int32, pageSize int32, accountID int64, fields map[string]any) ([]azmodels.Repository, error)
}

// NewV1PAPServer creates a new PAP server.
func NewV1PAPServer(endpointCtx *azservices.EndpointContext, Service PAPService) (*V1PAPServer, error) {
	return &V1PAPServer{
		ctx:     endpointCtx,
		service: Service,
	}, nil
}

// V1PAPServer is the gRPC server for the PAP.
type V1PAPServer struct {
	UnimplementedV1PAPServiceServer
	ctx     *azservices.EndpointContext
	service PAPService
}

// CreateRepository creates a new repository.
func (s *V1PAPServer) CreateRepository(ctx context.Context, repositoryRequest *RepositoryCreateRequest) (*RepositoryResponse, error) {
	repository, err := s.service.CreateRepository(&azmodels.Repository{AccountID: repositoryRequest.AccountID, Name: repositoryRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentRepositoryToGrpcRepositoryResponse(repository)
}

// UpdateRepository updates a repository.
func (s *V1PAPServer) UpdateRepository(ctx context.Context, repositoryRequest *RepositoryUpdateRequest) (*RepositoryResponse, error) {
	repository, err := s.service.UpdateRepository((&azmodels.Repository{RepositoryID: repositoryRequest.RepositoryID, AccountID: repositoryRequest.AccountID, Name: repositoryRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentRepositoryToGrpcRepositoryResponse(repository)
}

// DeleteRepository deletes a repository.
func (s *V1PAPServer) DeleteRepository(ctx context.Context, repositoryRequest *RepositoryDeleteRequest) (*RepositoryResponse, error) {
	repository, err := s.service.DeleteRepository(repositoryRequest.AccountID, repositoryRequest.RepositoryID)
	if err != nil {
		return nil, err
	}
	return MapAgentRepositoryToGrpcRepositoryResponse(repository)
}

// FetchRepositories returns all repositories.
func (s *V1PAPServer) FetchRepositories(repositoryRequest *RepositoryFetchRequest, stream grpc.ServerStreamingServer[RepositoryResponse]) (error) {
	fields := map[string]any{}
	fields[azmodels.FieldRepositoryAccountID] = repositoryRequest.AccountID
	if repositoryRequest.Name != nil {
		fields[azmodels.FieldRepositoryName] = *repositoryRequest.Name
	}
	if repositoryRequest.RepositoryID != nil {
		fields[azmodels.FieldRepositoryRepositoryID] = *repositoryRequest.RepositoryID
	}
	page := int32(0)
	if repositoryRequest.Page != nil {
		page = int32(*repositoryRequest.Page)
	}
	pageSize := int32(0)
	if repositoryRequest.PageSize != nil {
		pageSize = int32(*repositoryRequest.PageSize)
	}
	repositories, err := s.service.FetchRepositories(page, pageSize, repositoryRequest.AccountID, fields)
	if err != nil {
		return err
	}
	for _, repository := range repositories {
		cvtedRepository, err := MapAgentRepositoryToGrpcRepositoryResponse(&repository)
		if err != nil {
			return err
		}
		stream.SendMsg(cvtedRepository)
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
	var hostHandler notpstatemachines.HostHandler = func(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
		handlerReturn := &notpstatemachines.HostHandlerRuturn {
			Packetables: packets,
		}
		return handlerReturn, nil
	}
	stateMachine, err := notpstatemachines.NewLeaderStateMachine(hostHandler, transportLayer)
	if err != nil {
		return nil, err
	}
	return stateMachine, nil
}

// NOTPStream handles bidirectional stream using the NOTP protocol.
func (s *V1PAPServer) NOTPStream(stream grpc.BidiStreamingServer[PackMessage, PackMessage]) error {
	stateMachine, err := s.createWiredStateMachine(stream)
	if err != nil {
		return err
	}
	err = stateMachine.Run(notpstatemachines.UnknownFlowType)
	if err != nil {
		return err
	}
	return nil
}
