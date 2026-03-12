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
	"encoding/json"
	"errors"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

// mapStorageError maps storage sentinel errors to gRPC status codes.
func mapStorageError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, azstorage.ErrNotFound):
		return status.Errorf(codes.NotFound, "%v", err)
	case errors.Is(err, azstorage.ErrAlreadyExists):
		return status.Errorf(codes.AlreadyExists, "%v", err)
	case errors.Is(err, azstorage.ErrConflict):
		return status.Errorf(codes.Aborted, "%v", err)
	case errors.Is(err, azstorage.ErrInvalidInput):
		return status.Errorf(codes.InvalidArgument, "%v", err)
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

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
	// PushAdvertise handles the push advertise step.
	PushAdvertise(ctx context.Context, req *pap.PushAdvertiseRequest) (*pap.PushAdvertiseResponse, error)
	// PushTransfer handles the push transfer step.
	PushTransfer(ctx context.Context, req *pap.PushTransferRequest) (*pap.PushTransferResponse, error)
	// PullState handles the pull state step.
	PullState(ctx context.Context, req *pap.PullStateRequest) (*pap.PullStateResponse, error)
	// PullNegotiate handles the pull negotiate step.
	PullNegotiate(ctx context.Context, req *pap.PullNegotiateRequest) (*pap.PullNegotiateResponse, error)
	// PullObjects handles the pull objects step.
	PullObjects(ctx context.Context, req *pap.PullObjectsRequest) (*pap.PullObjectsResponse, error)
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
		return nil, mapStorageError(err)
	}
	return MapAgentLedgerToGrpcLedgerResponse(ledger)
}

// UpdateLedger updates a ledger.
func (s *PAPServer) UpdateLedger(ctx context.Context, ledgerRequest *LedgerUpdateRequest) (*LedgerResponse, error) {
	ledger, err := s.service.UpdateLedger(ctx, (&pap.Ledger{LedgerID: ledgerRequest.LedgerID, ZoneID: ledgerRequest.ZoneID, Name: ledgerRequest.Name}))
	if err != nil {
		return nil, mapStorageError(err)
	}
	return MapAgentLedgerToGrpcLedgerResponse(ledger)
}

// DeleteLedger deletes a ledger.
func (s *PAPServer) DeleteLedger(ctx context.Context, ledgerRequest *LedgerDeleteRequest) (*LedgerResponse, error) {
	ledger, err := s.service.DeleteLedger(ctx, ledgerRequest.ZoneID, ledgerRequest.LedgerID)
	if err != nil {
		return nil, mapStorageError(err)
	}
	return MapAgentLedgerToGrpcLedgerResponse(ledger)
}

// FetchLedgers returns all ledgers.
func (s *PAPServer) FetchLedgers(ledgerRequest *LedgerFetchRequest, stream grpc.ServerStreamingServer[LedgerResponse]) error {
	ctx := stream.Context()
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
	ledgers, err := s.service.FetchLedgers(ctx, page, pageSize, ledgerRequest.ZoneID, fields)
	if err != nil {
		return mapStorageError(err)
	}
	for _, ledger := range ledgers {
		cvtedLedger, err := MapAgentLedgerToGrpcLedgerResponse(&ledger)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to map ledger response: %v", err)
		}
		if err := stream.SendMsg(cvtedLedger); err != nil {
			return status.Errorf(codes.Internal, "failed to send ledger response: %v", err)
		}
	}
	return nil
}

// PushAdvertise handles the push advertise step.
func (s *PAPServer) PushAdvertise(ctx context.Context, in *PackMessage) (*PackMessage, error) {
	var req pap.PushAdvertiseRequest
	if err := json.Unmarshal(in.Data, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	resp, err := s.service.PushAdvertise(ctx, &req)
	if err != nil {
		return nil, mapStorageError(err)
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal response: %v", err)
	}
	return &PackMessage{Data: data}, nil
}

// PushTransfer handles the push transfer step.
func (s *PAPServer) PushTransfer(ctx context.Context, in *PackMessage) (*PackMessage, error) {
	var req pap.PushTransferRequest
	if err := json.Unmarshal(in.Data, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	resp, err := s.service.PushTransfer(ctx, &req)
	if err != nil {
		return nil, mapStorageError(err)
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal response: %v", err)
	}
	return &PackMessage{Data: data}, nil
}

// PullState handles the pull state step.
func (s *PAPServer) PullState(ctx context.Context, in *PackMessage) (*PackMessage, error) {
	var req pap.PullStateRequest
	if err := json.Unmarshal(in.Data, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	resp, err := s.service.PullState(ctx, &req)
	if err != nil {
		return nil, mapStorageError(err)
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal response: %v", err)
	}
	return &PackMessage{Data: data}, nil
}

// PullNegotiate handles the pull negotiate step.
func (s *PAPServer) PullNegotiate(ctx context.Context, in *PackMessage) (*PackMessage, error) {
	var req pap.PullNegotiateRequest
	if err := json.Unmarshal(in.Data, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	resp, err := s.service.PullNegotiate(ctx, &req)
	if err != nil {
		return nil, mapStorageError(err)
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal response: %v", err)
	}
	return &PackMessage{Data: data}, nil
}

// PullObjects handles the pull objects step.
func (s *PAPServer) PullObjects(ctx context.Context, in *PackMessage) (*PackMessage, error) {
	var req pap.PullObjectsRequest
	if err := json.Unmarshal(in.Data, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	resp, err := s.service.PullObjects(ctx, &req)
	if err != nil {
		return nil, mapStorageError(err)
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal response: %v", err)
	}
	return &PackMessage{Data: data}, nil
}
