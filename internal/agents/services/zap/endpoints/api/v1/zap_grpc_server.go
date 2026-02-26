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

	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/transport/models/zap"
	"google.golang.org/grpc"
)

// ZAPService is the service for the ZAP.
type ZAPService interface {
	Setup() error

	// CreateZone creates a new zone.
	CreateZone(zone *zap.Zone) (*zap.Zone, error)
	// UpdateZone updates a zone.
	UpdateZone(zone *zap.Zone) (*zap.Zone, error)
	// DeleteZone deletes a zone.
	DeleteZone(zoneID int64) (*zap.Zone, error)
	// FetchZones returns all zones.
	FetchZones(page int32, pageSize int32, filter map[string]any) ([]zap.Zone, error)
}

// NewZAPServer creates a new ZAP server.
func NewZAPServer(endpointCtx *services.EndpointContext, service ZAPService) (*ZAPServer, error) {
	return &ZAPServer{
		ctx:     endpointCtx,
		service: service,
	}, nil
}

// ZAPServer is the gRPC server for the ZAP.
type ZAPServer struct {
	UnimplementedV1ZAPServiceServer
	ctx     *services.EndpointContext
	service ZAPService
}

// CreateZone creates a new zone.
func (s *ZAPServer) CreateZone(_ context.Context, zoneRequest *ZoneCreateRequest) (*ZoneResponse, error) {
	zone, err := s.service.CreateZone(&zap.Zone{Name: zoneRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentZoneToGrpcZoneResponse(zone)
}

// UpdateZone updates a zone.
func (s *ZAPServer) UpdateZone(_ context.Context, zoneRequest *ZoneUpdateRequest) (*ZoneResponse, error) {
	zone, err := s.service.UpdateZone((&zap.Zone{ZoneID: zoneRequest.ZoneID, Name: zoneRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentZoneToGrpcZoneResponse(zone)
}

// DeleteZone deletes a zone.
func (s *ZAPServer) DeleteZone(_ context.Context, zoneRequest *ZoneDeleteRequest) (*ZoneResponse, error) {
	zone, err := s.service.DeleteZone(zoneRequest.ZoneID)
	if err != nil {
		return nil, err
	}
	return MapAgentZoneToGrpcZoneResponse(zone)
}

// FetchZones returns all zones.
func (s *ZAPServer) FetchZones(zoneRequest *ZoneFetchRequest, stream grpc.ServerStreamingServer[ZoneResponse]) error {
	fields := map[string]any{}
	if zoneRequest.ZoneID != nil {
		fields[zap.FieldZoneZoneID] = *zoneRequest.ZoneID
	}
	if zoneRequest.Name != nil {
		fields[zap.FieldZoneName] = *zoneRequest.Name
	}
	page := int32(0)
	if zoneRequest.Page != nil {
		page = *zoneRequest.Page
	}
	pageSize := int32(0)
	if zoneRequest.PageSize != nil {
		pageSize = *zoneRequest.PageSize
	}
	zones, err := s.service.FetchZones(page, pageSize, fields)
	if err != nil {
		return err
	}
	for _, zone := range zones {
		cvtedZone, err := MapAgentZoneToGrpcZoneResponse(&zone)
		if err != nil {
			return err
		}
		if err := stream.SendMsg(cvtedZone); err != nil {
			return err
		}
	}
	return nil
}
