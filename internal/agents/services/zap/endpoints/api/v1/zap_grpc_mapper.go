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
	"google.golang.org/protobuf/types/known/timestamppb"

	azmodelszap "github.com/permguard/permguard/pkg/transport/models/zap"
)

// MapPointerStringToString maps a pointer string to a string.
func MapPointerStringToString(str *string) string {
	response := ""
	if str != nil {
		response = *str
	}
	return response
}

// MapGrpcZoneResponseToAgentZone maps the gRPC zone to the agent zone.
func MapGrpcZoneResponseToAgentZone(zone *ZoneResponse) (*azmodelszap.Zone, error) {
	return &azmodelszap.Zone{
		ZoneID:    zone.ZoneID,
		CreatedAt: zone.CreatedAt.AsTime(),
		UpdatedAt: zone.UpdatedAt.AsTime(),
		Name:      zone.Name,
	}, nil
}

// MapAgentZoneToGrpcZoneResponse maps the agent zone to the gRPC zone.
func MapAgentZoneToGrpcZoneResponse(zone *azmodelszap.Zone) (*ZoneResponse, error) {
	return &ZoneResponse{
		ZoneID:    zone.ZoneID,
		CreatedAt: timestamppb.New(zone.CreatedAt),
		UpdatedAt: timestamppb.New(zone.UpdatedAt),
		Name:      zone.Name,
	}, nil
}

// MapGrpcTenantResponseToAgentTenant maps the gRPC tenant to the agent tenant.
func MapGrpcTenantResponseToAgentTenant(tenant *TenantResponse) (*azmodelszap.Tenant, error) {
	return &azmodelszap.Tenant{
		TenantID:  tenant.TenantID,
		CreatedAt: tenant.CreatedAt.AsTime(),
		UpdatedAt: tenant.UpdatedAt.AsTime(),
		ZoneID:    tenant.ZoneID,
		Name:      tenant.Name,
	}, nil
}

// MapAgentTenantToGrpcTenantResponse maps the agent tenant to the gRPC tenant.
func MapAgentTenantToGrpcTenantResponse(tenant *azmodelszap.Tenant) (*TenantResponse, error) {
	return &TenantResponse{
		TenantID:  tenant.TenantID,
		CreatedAt: timestamppb.New(tenant.CreatedAt),
		UpdatedAt: timestamppb.New(tenant.UpdatedAt),
		ZoneID:    tenant.ZoneID,
		Name:      tenant.Name,
	}, nil
}

// MapGrpcIdentitySourceResponseToAgentIdentitySource maps the gRPC identity source to the agent identity source.
func MapGrpcIdentitySourceResponseToAgentIdentitySource(identitySource *IdentitySourceResponse) (*azmodelszap.IdentitySource, error) {
	return &azmodelszap.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		CreatedAt:        identitySource.CreatedAt.AsTime(),
		UpdatedAt:        identitySource.UpdatedAt.AsTime(),
		ZoneID:           identitySource.ZoneID,
		Name:             identitySource.Name,
	}, nil
}

// MapAgentIdentitySourceToGrpcIdentitySourceResponse maps the agent identity source to the gRPC identity source.
func MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource *azmodelszap.IdentitySource) (*IdentitySourceResponse, error) {
	return &IdentitySourceResponse{
		IdentitySourceID: identitySource.IdentitySourceID,
		CreatedAt:        timestamppb.New(identitySource.CreatedAt),
		UpdatedAt:        timestamppb.New(identitySource.UpdatedAt),
		ZoneID:           identitySource.ZoneID,
		Name:             identitySource.Name,
	}, nil
}

// MapGrpcIdentityResponseToAgentIdentity maps the gRPC identity to the agent identity.
func MapGrpcIdentityResponseToAgentIdentity(identity *IdentityResponse) (*azmodelszap.Identity, error) {
	return &azmodelszap.Identity{
		IdentityID:       identity.IdentityID,
		CreatedAt:        identity.CreatedAt.AsTime(),
		UpdatedAt:        identity.UpdatedAt.AsTime(),
		ZoneID:           identity.ZoneID,
		IdentitySourceID: identity.IdentitySourceID,
		Kind:             identity.Kind,
		Name:             identity.Name,
	}, nil
}

// MapAgentIdentityToGrpcIdentityResponse maps the agent identity to the gRPC identity.
func MapAgentIdentityToGrpcIdentityResponse(identity *azmodelszap.Identity) (*IdentityResponse, error) {
	return &IdentityResponse{
		IdentityID:       identity.IdentityID,
		CreatedAt:        timestamppb.New(identity.CreatedAt),
		UpdatedAt:        timestamppb.New(identity.UpdatedAt),
		ZoneID:           identity.ZoneID,
		IdentitySourceID: identity.IdentitySourceID,
		Kind:             identity.Kind,
		Name:             identity.Name,
	}, nil
}
