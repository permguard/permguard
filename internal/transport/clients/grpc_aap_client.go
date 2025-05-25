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

package clients

import (
	"context"
	"errors"
	"io"

	zapv1 "github.com/permguard/permguard/internal/agents/services/zap/endpoints/api/v1"
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

// CreateZone creates a new zone.
func (c *GrpcZAPClient) CreateZone(name string) (*zap.Zone, error) {
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	zone, err := client.CreateZone(context.Background(), &zapv1.ZoneCreateRequest{Name: name})
	if err != nil {
		return nil, err
	}
	return zapv1.MapGrpcZoneResponseToAgentZone(zone)
}

// UpdateZone updates a zone.
func (c *GrpcZAPClient) UpdateZone(zone *zap.Zone) (*zap.Zone, error) {
	if zone == nil {
		return nil, errors.New("grpc-client: invalid zone instance")
	}
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	updatedZone, err := client.UpdateZone(context.Background(), &zapv1.ZoneUpdateRequest{
		ZoneID: zone.ZoneID,
		Name:   zone.Name,
	})
	if err != nil {
		return nil, err
	}
	return zapv1.MapGrpcZoneResponseToAgentZone(updatedZone)
}

// DeleteZone deletes a zone.
func (c *GrpcZAPClient) DeleteZone(zoneID int64) (*zap.Zone, error) {
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	zone, err := client.DeleteZone(context.Background(), &zapv1.ZoneDeleteRequest{ZoneID: zoneID})
	if err != nil {
		return nil, err
	}
	return zapv1.MapGrpcZoneResponseToAgentZone(zone)
}

// FetchZones returns all zones.
func (c *GrpcZAPClient) FetchZones(page int32, pageSize int32) ([]zap.Zone, error) {
	return c.FetchZonesBy(page, pageSize, 0, "")
}

// FetchZonesByID returns all zones filtering by zone id.
func (c *GrpcZAPClient) FetchZonesByID(page int32, pageSize int32, zoneID int64) ([]zap.Zone, error) {
	return c.FetchZonesBy(page, pageSize, zoneID, "")
}

// FetchZonesByName returns all zones filtering by name.
func (c *GrpcZAPClient) FetchZonesByName(page int32, pageSize int32, name string) ([]zap.Zone, error) {
	return c.FetchZonesBy(page, pageSize, 0, name)
}

// FetchZonesBy returns all zones filtering by zone id and name.
func (c *GrpcZAPClient) FetchZonesBy(page int32, pageSize int32, zoneID int64, name string) ([]zap.Zone, error) {
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	zoneFetchRequest := &zapv1.ZoneFetchRequest{}
	zoneFetchRequest.Page = &page
	zoneFetchRequest.PageSize = &pageSize
	if zoneID > 0 {
		zoneFetchRequest.ZoneID = &zoneID
	}
	if name != "" {
		zoneFetchRequest.Name = &name
	}
	stream, err := client.FetchZones(context.Background(), zoneFetchRequest)
	if err != nil {
		return nil, err
	}
	zones := []zap.Zone{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		zone, err := zapv1.MapGrpcZoneResponseToAgentZone(response)
		if err != nil {
			return nil, err
		}
		zones = append(zones, *zone)
	}
	return zones, nil
}
