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
	"io"

	azapiv1zap "github.com/permguard/permguard/internal/agents/services/zap/endpoints/api/v1"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelzap "github.com/permguard/permguard/pkg/transport/models/zap"
)

// CreateZone creates a new zone.
func (c *GrpcZAPClient) CreateZone(name string) (*azmodelzap.Zone, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	zone, err := client.CreateZone(context.Background(), &azapiv1zap.ZoneCreateRequest{Name: name})
	if err != nil {
		return nil, err
	}
	return azapiv1zap.MapGrpcZoneResponseToAgentZone(zone)
}

// UpdateZone updates a zone.
func (c *GrpcZAPClient) UpdateZone(zone *azmodelzap.Zone) (*azmodelzap.Zone, error) {
	if zone == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientGeneric, "invalid zone instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedZone, err := client.UpdateZone(context.Background(), &azapiv1zap.ZoneUpdateRequest{
		ZoneID: zone.ZoneID,
		Name:   zone.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1zap.MapGrpcZoneResponseToAgentZone(updatedZone)
}

// DeleteZone deletes a zone.
func (c *GrpcZAPClient) DeleteZone(zoneID int64) (*azmodelzap.Zone, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	zone, err := client.DeleteZone(context.Background(), &azapiv1zap.ZoneDeleteRequest{ZoneID: zoneID})
	if err != nil {
		return nil, err
	}
	return azapiv1zap.MapGrpcZoneResponseToAgentZone(zone)
}

// FetchZones returns all zones.
func (c *GrpcZAPClient) FetchZones(page int32, pageSize int32) ([]azmodelzap.Zone, error) {
	return c.FetchZonesBy(page, pageSize, 0, "")
}

// FetchZonesByID returns all zones filtering by zone id.
func (c *GrpcZAPClient) FetchZonesByID(page int32, pageSize int32, zoneID int64) ([]azmodelzap.Zone, error) {
	return c.FetchZonesBy(page, pageSize, zoneID, "")
}

// FetchZonesByName returns all zones filtering by name.
func (c *GrpcZAPClient) FetchZonesByName(page int32, pageSize int32, name string) ([]azmodelzap.Zone, error) {
	return c.FetchZonesBy(page, pageSize, 0, name)
}

// FetchZonesBy returns all zones filtering by zone id and name.
func (c *GrpcZAPClient) FetchZonesBy(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.Zone, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	zoneFetchRequest := &azapiv1zap.ZoneFetchRequest{}
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
	zones := []azmodelzap.Zone{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		zone, err := azapiv1zap.MapGrpcZoneResponseToAgentZone(response)
		if err != nil {
			return nil, err
		}
		zones = append(zones, *zone)
	}
	return zones, nil
}
