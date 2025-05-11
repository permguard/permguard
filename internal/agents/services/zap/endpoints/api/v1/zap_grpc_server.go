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

	// CreateIdentitySource creates a new identity source.
	CreateIdentitySource(identitySource *zap.IdentitySource) (*zap.IdentitySource, error)
	// UpdateIdentitySource updates an identity source.
	UpdateIdentitySource(identitySource *zap.IdentitySource) (*zap.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(zoneID int64, identitySourceID string) (*zap.IdentitySource, error)
	// FetchIdentitySources returns all identity sources.
	FetchIdentitySources(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]zap.IdentitySource, error)

	// CreateIdentity creates a new identity.
	CreateIdentity(identity *zap.Identity) (*zap.Identity, error)
	// UpdateIdentity updates an identity.
	UpdateIdentity(identity *zap.Identity) (*zap.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(zoneID int64, identityID string) (*zap.Identity, error)
	// FetchIdentities returns all identities.
	FetchIdentities(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]zap.Identity, error)

	// CreateTenant creates a new tenant.
	CreateTenant(tenant *zap.Tenant) (*zap.Tenant, error)
	// UpdateTenant updates a tenant.
	UpdateTenant(tenant *zap.Tenant) (*zap.Tenant, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(zoneID int64, tenantID string) (*zap.Tenant, error)
	// FetchTenants returns all tenants.
	FetchTenants(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]zap.Tenant, error)
}

// NewV1ZAPServer creates a new ZAP server.
func NewV1ZAPServer(endpointCtx *services.EndpointContext, Service ZAPService) (*V1ZAPServer, error) {
	return &V1ZAPServer{
		ctx:     endpointCtx,
		service: Service,
	}, nil
}

// V1ZAPServer is the gRPC server for the ZAP.
type V1ZAPServer struct {
	UnimplementedV1ZAPServiceServer
	ctx     *services.EndpointContext
	service ZAPService
}

// CreateZone creates a new zone.
func (s *V1ZAPServer) CreateZone(ctx context.Context, zoneRequest *ZoneCreateRequest) (*ZoneResponse, error) {
	zone, err := s.service.CreateZone(&zap.Zone{Name: zoneRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentZoneToGrpcZoneResponse(zone)
}

// UpdateZone updates a zone.
func (s *V1ZAPServer) UpdateZone(ctx context.Context, zoneRequest *ZoneUpdateRequest) (*ZoneResponse, error) {
	zone, err := s.service.UpdateZone((&zap.Zone{ZoneID: zoneRequest.ZoneID, Name: zoneRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentZoneToGrpcZoneResponse(zone)
}

// DeleteZone deletes a zone.
func (s *V1ZAPServer) DeleteZone(ctx context.Context, zoneRequest *ZoneDeleteRequest) (*ZoneResponse, error) {
	zone, err := s.service.DeleteZone(zoneRequest.ZoneID)
	if err != nil {
		return nil, err
	}
	return MapAgentZoneToGrpcZoneResponse(zone)
}

// FetchZones returns all zones.
func (s *V1ZAPServer) FetchZones(zoneRequest *ZoneFetchRequest, stream grpc.ServerStreamingServer[ZoneResponse]) error {
	fields := map[string]any{}
	if zoneRequest.ZoneID != nil {
		fields[zap.FieldZoneZoneID] = *zoneRequest.ZoneID
	}
	if zoneRequest.Name != nil {
		fields[zap.FieldZoneName] = *zoneRequest.Name

	}
	page := int32(0)
	if zoneRequest.Page != nil {
		page = int32(*zoneRequest.Page)
	}
	pageSize := int32(0)
	if zoneRequest.PageSize != nil {
		pageSize = int32(*zoneRequest.PageSize)
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
		stream.SendMsg(cvtedZone)
	}
	return nil
}

// CreateIdentitySource creates a new identity source.
func (s *V1ZAPServer) CreateIdentitySource(ctx context.Context, identitySourceRequest *IdentitySourceCreateRequest) (*IdentitySourceResponse, error) {
	identitySource, err := s.service.CreateIdentitySource(&zap.IdentitySource{ZoneID: identitySourceRequest.ZoneID, Name: identitySourceRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource)
}

// UpdateIdentitySource updates an identity source.
func (s *V1ZAPServer) UpdateIdentitySource(ctx context.Context, identitySourceRequest *IdentitySourceUpdateRequest) (*IdentitySourceResponse, error) {
	identitySource, err := s.service.UpdateIdentitySource((&zap.IdentitySource{IdentitySourceID: identitySourceRequest.IdentitySourceID, ZoneID: identitySourceRequest.ZoneID, Name: identitySourceRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource)
}

// DeleteIdentitySource deletes an identity source.
func (s *V1ZAPServer) DeleteIdentitySource(ctx context.Context, identitySourceRequest *IdentitySourceDeleteRequest) (*IdentitySourceResponse, error) {
	identitySource, err := s.service.DeleteIdentitySource(identitySourceRequest.ZoneID, identitySourceRequest.IdentitySourceID)
	if err != nil {
		return nil, err
	}
	return MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource)
}

// FetchIdentitySources returns all identity sources.
func (s *V1ZAPServer) FetchIdentitySources(identitySourceRequest *IdentitySourceFetchRequest, stream grpc.ServerStreamingServer[IdentitySourceResponse]) error {
	fields := map[string]any{}
	fields[zap.FieldIdentitySourceZoneID] = identitySourceRequest.ZoneID
	if identitySourceRequest.Name != nil {
		fields[zap.FieldIdentitySourceName] = *identitySourceRequest.Name
	}
	if identitySourceRequest.IdentitySourceID != nil {
		fields[zap.FieldIdentitySourceIdentitySourceID] = *identitySourceRequest.IdentitySourceID
	}
	page := int32(0)
	if identitySourceRequest.Page != nil {
		page = int32(*identitySourceRequest.Page)
	}
	pageSize := int32(0)
	if identitySourceRequest.PageSize != nil {
		pageSize = int32(*identitySourceRequest.PageSize)
	}
	identitySources, err := s.service.FetchIdentitySources(page, pageSize, identitySourceRequest.ZoneID, fields)
	if err != nil {
		return err
	}
	for _, identitySource := range identitySources {
		cvtedIdentitySource, err := MapAgentIdentitySourceToGrpcIdentitySourceResponse(&identitySource)
		if err != nil {
			return err
		}
		stream.SendMsg(cvtedIdentitySource)
	}
	return nil
}

// CreateIdentity creates a new identity.
func (s *V1ZAPServer) CreateIdentity(ctx context.Context, identityRequest *IdentityCreateRequest) (*IdentityResponse, error) {
	identity, err := s.service.CreateIdentity(&zap.Identity{ZoneID: identityRequest.ZoneID, IdentitySourceID: identityRequest.IdentitySourceID, Kind: identityRequest.Kind, Name: identityRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentIdentityToGrpcIdentityResponse(identity)
}

// UpdateIdentity updates an identity.
func (s *V1ZAPServer) UpdateIdentity(ctx context.Context, identityRequest *IdentityUpdateRequest) (*IdentityResponse, error) {
	identity, err := s.service.UpdateIdentity((&zap.Identity{IdentityID: identityRequest.IdentityID, ZoneID: identityRequest.ZoneID, Kind: identityRequest.Kind, Name: identityRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentIdentityToGrpcIdentityResponse(identity)
}

// DeleteIdentity deletes an identity.
func (s *V1ZAPServer) DeleteIdentity(ctx context.Context, identityRequest *IdentityDeleteRequest) (*IdentityResponse, error) {
	identity, err := s.service.DeleteIdentity(identityRequest.ZoneID, identityRequest.IdentityID)
	if err != nil {
		return nil, err
	}
	return MapAgentIdentityToGrpcIdentityResponse(identity)
}

// FetchIdentities returns all identities.
func (s *V1ZAPServer) FetchIdentities(identityRequest *IdentityFetchRequest, stream grpc.ServerStreamingServer[IdentityResponse]) error {
	fields := map[string]any{}
	fields[zap.FieldIdentityZoneID] = identityRequest.ZoneID
	if identityRequest.IdentitySourceID != nil {
		fields[zap.FieldIdentityIdentitySourceID] = *identityRequest.IdentitySourceID
	}
	if identityRequest.IdentityID != nil {
		fields[zap.FieldIdentityIdentityID] = *identityRequest.IdentityID
	}
	if identityRequest.Kind != nil {
		fields[zap.FieldIdentityKind] = *identityRequest.Kind
	}
	if identityRequest.Name != nil {
		fields[zap.FieldIdentityName] = *identityRequest.Name
	}
	page := int32(0)
	if identityRequest.Page != nil {
		page = int32(*identityRequest.Page)
	}
	pageSize := int32(0)
	if identityRequest.PageSize != nil {
		pageSize = int32(*identityRequest.PageSize)
	}
	identities, err := s.service.FetchIdentities(page, pageSize, identityRequest.ZoneID, fields)
	if err != nil {
		return err
	}
	for _, identity := range identities {
		cvtedIdentity, err := MapAgentIdentityToGrpcIdentityResponse(&identity)
		if err != nil {
			return err
		}
		stream.SendMsg(cvtedIdentity)
	}
	return nil
}

// CreateTenant creates a new tenant.
func (s *V1ZAPServer) CreateTenant(ctx context.Context, tenantRequest *TenantCreateRequest) (*TenantResponse, error) {
	tenant, err := s.service.CreateTenant(&zap.Tenant{ZoneID: tenantRequest.ZoneID, Name: tenantRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentTenantToGrpcTenantResponse(tenant)
}

// UpdateTenant updates a tenant.
func (s *V1ZAPServer) UpdateTenant(ctx context.Context, tenantRequest *TenantUpdateRequest) (*TenantResponse, error) {
	tenant, err := s.service.UpdateTenant((&zap.Tenant{TenantID: tenantRequest.TenantID, ZoneID: tenantRequest.ZoneID, Name: tenantRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentTenantToGrpcTenantResponse(tenant)
}

// DeleteTenant deletes a tenant.
func (s *V1ZAPServer) DeleteTenant(ctx context.Context, tenantRequest *TenantDeleteRequest) (*TenantResponse, error) {
	tenant, err := s.service.DeleteTenant(tenantRequest.ZoneID, tenantRequest.TenantID)
	if err != nil {
		return nil, err
	}
	return MapAgentTenantToGrpcTenantResponse(tenant)
}

// FetchTenants returns all tenants.
func (s *V1ZAPServer) FetchTenants(tenantRequest *TenantFetchRequest, stream grpc.ServerStreamingServer[TenantResponse]) error {
	fields := map[string]any{}
	fields[zap.FieldTenantZoneID] = tenantRequest.ZoneID
	if tenantRequest.Name != nil {
		fields[zap.FieldTenantName] = *tenantRequest.Name
	}
	if tenantRequest.TenantID != nil {
		fields[zap.FieldTenantTenantID] = *tenantRequest.TenantID
	}
	page := int32(0)
	if tenantRequest.Page != nil {
		page = int32(*tenantRequest.Page)
	}
	pageSize := int32(0)
	if tenantRequest.PageSize != nil {
		pageSize = int32(*tenantRequest.PageSize)
	}
	tenants, err := s.service.FetchTenants(page, pageSize, tenantRequest.ZoneID, fields)
	if err != nil {
		return err
	}
	for _, tenant := range tenants {
		cvtedTenant, err := MapAgentTenantToGrpcTenantResponse(&tenant)
		if err != nil {
			return err
		}
		stream.SendMsg(cvtedTenant)
	}
	return nil
}
