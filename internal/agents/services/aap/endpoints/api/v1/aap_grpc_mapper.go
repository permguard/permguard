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

	azmodelsaap "github.com/permguard/permguard/pkg/transport/models/aap"
)

// MapPointerStringToString maps a pointer string to a string.
func MapPointerStringToString(str *string) string {
	response := ""
	if str != nil {
		response = *str
	}
	return response
}

// MapGrpcApplicationResponseToAgentApplication maps the gRPC application to the agent application.
func MapGrpcApplicationResponseToAgentApplication(application *ApplicationResponse) (*azmodelsaap.Application, error) {
	return &azmodelsaap.Application{
		ApplicationID: application.ApplicationID,
		CreatedAt:     application.CreatedAt.AsTime(),
		UpdatedAt:     application.UpdatedAt.AsTime(),
		Name:          application.Name,
	}, nil
}

// MapAgentApplicationToGrpcApplicationResponse maps the agent application to the gRPC application.
func MapAgentApplicationToGrpcApplicationResponse(application *azmodelsaap.Application) (*ApplicationResponse, error) {
	return &ApplicationResponse{
		ApplicationID: application.ApplicationID,
		CreatedAt:     timestamppb.New(application.CreatedAt),
		UpdatedAt:     timestamppb.New(application.UpdatedAt),
		Name:          application.Name,
	}, nil
}

// MapGrpcTenantResponseToAgentTenant maps the gRPC tenant to the agent tenant.
func MapGrpcTenantResponseToAgentTenant(tenant *TenantResponse) (*azmodelsaap.Tenant, error) {
	return &azmodelsaap.Tenant{
		TenantID:      tenant.TenantID,
		CreatedAt:     tenant.CreatedAt.AsTime(),
		UpdatedAt:     tenant.UpdatedAt.AsTime(),
		ApplicationID: tenant.ApplicationID,
		Name:          tenant.Name,
	}, nil
}

// MapAgentTenantToGrpcTenantResponse maps the agent tenant to the gRPC tenant.
func MapAgentTenantToGrpcTenantResponse(tenant *azmodelsaap.Tenant) (*TenantResponse, error) {
	return &TenantResponse{
		TenantID:      tenant.TenantID,
		CreatedAt:     timestamppb.New(tenant.CreatedAt),
		UpdatedAt:     timestamppb.New(tenant.UpdatedAt),
		ApplicationID: tenant.ApplicationID,
		Name:          tenant.Name,
	}, nil
}

// MapGrpcIdentitySourceResponseToAgentIdentitySource maps the gRPC identity source to the agent identity source.
func MapGrpcIdentitySourceResponseToAgentIdentitySource(identitySource *IdentitySourceResponse) (*azmodelsaap.IdentitySource, error) {
	return &azmodelsaap.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		CreatedAt:        identitySource.CreatedAt.AsTime(),
		UpdatedAt:        identitySource.UpdatedAt.AsTime(),
		ApplicationID:    identitySource.ApplicationID,
		Name:             identitySource.Name,
	}, nil
}

// MapAgentIdentitySourceToGrpcIdentitySourceResponse maps the agent identity source to the gRPC identity source.
func MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource *azmodelsaap.IdentitySource) (*IdentitySourceResponse, error) {
	return &IdentitySourceResponse{
		IdentitySourceID: identitySource.IdentitySourceID,
		CreatedAt:        timestamppb.New(identitySource.CreatedAt),
		UpdatedAt:        timestamppb.New(identitySource.UpdatedAt),
		ApplicationID:    identitySource.ApplicationID,
		Name:             identitySource.Name,
	}, nil
}

// MapGrpcIdentityResponseToAgentIdentity maps the gRPC identity to the agent identity.
func MapGrpcIdentityResponseToAgentIdentity(identity *IdentityResponse) (*azmodelsaap.Identity, error) {
	return &azmodelsaap.Identity{
		IdentityID:       identity.IdentityID,
		CreatedAt:        identity.CreatedAt.AsTime(),
		UpdatedAt:        identity.UpdatedAt.AsTime(),
		ApplicationID:    identity.ApplicationID,
		IdentitySourceID: identity.IdentitySourceID,
		Kind:             identity.Kind,
		Name:             identity.Name,
	}, nil
}

// MapAgentIdentityToGrpcIdentityResponse maps the agent identity to the gRPC identity.
func MapAgentIdentityToGrpcIdentityResponse(identity *azmodelsaap.Identity) (*IdentityResponse, error) {
	return &IdentityResponse{
		IdentityID:       identity.IdentityID,
		CreatedAt:        timestamppb.New(identity.CreatedAt),
		UpdatedAt:        timestamppb.New(identity.UpdatedAt),
		ApplicationID:    identity.ApplicationID,
		IdentitySourceID: identity.IdentitySourceID,
		Kind:             identity.Kind,
		Name:             identity.Name,
	}, nil
}
