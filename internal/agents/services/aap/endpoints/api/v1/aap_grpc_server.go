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

	azservices "github.com/permguard/permguard/pkg/agents/services"
	azmodelsaap "github.com/permguard/permguard/pkg/transport/models/aap"
	grpc "google.golang.org/grpc"
)

// AAPService is the service for the AAP.
type AAPService interface {
	Setup() error

	// CreateApplication creates a new application.
	CreateApplication(application *azmodelsaap.Application) (*azmodelsaap.Application, error)
	// UpdateApplication updates an application.
	UpdateApplication(application *azmodelsaap.Application) (*azmodelsaap.Application, error)
	// DeleteApplication deletes an application.
	DeleteApplication(applicationID int64) (*azmodelsaap.Application, error)
	// FetchApplications returns all applications.
	FetchApplications(page int32, pageSize int32, filter map[string]any) ([]azmodelsaap.Application, error)

	// CreateIdentitySource creates a new identity source.
	CreateIdentitySource(identitySource *azmodelsaap.IdentitySource) (*azmodelsaap.IdentitySource, error)
	// UpdateIdentitySource updates an identity source.
	UpdateIdentitySource(identitySource *azmodelsaap.IdentitySource) (*azmodelsaap.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(applicationID int64, identitySourceID string) (*azmodelsaap.IdentitySource, error)
	// FetchIdentitySources returns all identity sources.
	FetchIdentitySources(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodelsaap.IdentitySource, error)

	// CreateIdentity creates a new identity.
	CreateIdentity(identity *azmodelsaap.Identity) (*azmodelsaap.Identity, error)
	// UpdateIdentity updates an identity.
	UpdateIdentity(identity *azmodelsaap.Identity) (*azmodelsaap.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(applicationID int64, identityID string) (*azmodelsaap.Identity, error)
	// FetchIdentities returns all identities.
	FetchIdentities(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodelsaap.Identity, error)

	// CreateTenant creates a new tenant.
	CreateTenant(tenant *azmodelsaap.Tenant) (*azmodelsaap.Tenant, error)
	// UpdateTenant updates a tenant.
	UpdateTenant(tenant *azmodelsaap.Tenant) (*azmodelsaap.Tenant, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(applicationID int64, tenantID string) (*azmodelsaap.Tenant, error)
	// FetchTenants returns all tenants.
	FetchTenants(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodelsaap.Tenant, error)
}

// NewV1AAPServer creates a new AAP server.
func NewV1AAPServer(endpointCtx *azservices.EndpointContext, Service AAPService) (*V1AAPServer, error) {
	return &V1AAPServer{
		ctx:     endpointCtx,
		service: Service,
	}, nil
}

// V1AAPServer is the gRPC server for the AAP.
type V1AAPServer struct {
	UnimplementedV1AAPServiceServer
	ctx     *azservices.EndpointContext
	service AAPService
}

// CreateApplication creates a new application.
func (s *V1AAPServer) CreateApplication(ctx context.Context, applicationRequest *ApplicationCreateRequest) (*ApplicationResponse, error) {
	application, err := s.service.CreateApplication(&azmodelsaap.Application{Name: applicationRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentApplicationToGrpcApplicationResponse(application)
}

// UpdateApplication updates an application.
func (s *V1AAPServer) UpdateApplication(ctx context.Context, applicationRequest *ApplicationUpdateRequest) (*ApplicationResponse, error) {
	application, err := s.service.UpdateApplication((&azmodelsaap.Application{ApplicationID: applicationRequest.ApplicationID, Name: applicationRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentApplicationToGrpcApplicationResponse(application)
}

// DeleteApplication deletes an application.
func (s *V1AAPServer) DeleteApplication(ctx context.Context, applicationRequest *ApplicationDeleteRequest) (*ApplicationResponse, error) {
	application, err := s.service.DeleteApplication(applicationRequest.ApplicationID)
	if err != nil {
		return nil, err
	}
	return MapAgentApplicationToGrpcApplicationResponse(application)
}

// FetchApplications returns all applications.
func (s *V1AAPServer) FetchApplications(applicationRequest *ApplicationFetchRequest, stream grpc.ServerStreamingServer[ApplicationResponse]) error {
	fields := map[string]any{}
	if applicationRequest.ApplicationID != nil {
		fields[azmodelsaap.FieldApplicationApplicationID] = *applicationRequest.ApplicationID
	}
	if applicationRequest.Name != nil {
		fields[azmodelsaap.FieldApplicationName] = *applicationRequest.Name

	}
	page := int32(0)
	if applicationRequest.Page != nil {
		page = int32(*applicationRequest.Page)
	}
	pageSize := int32(0)
	if applicationRequest.PageSize != nil {
		pageSize = int32(*applicationRequest.PageSize)
	}
	applications, err := s.service.FetchApplications(page, pageSize, fields)
	if err != nil {
		return err
	}
	for _, application := range applications {
		cvtedApplication, err := MapAgentApplicationToGrpcApplicationResponse(&application)
		if err != nil {
			return err
		}
		stream.SendMsg(cvtedApplication)
	}
	return nil
}

// CreateIdentitySource creates a new identity source.
func (s *V1AAPServer) CreateIdentitySource(ctx context.Context, identitySourceRequest *IdentitySourceCreateRequest) (*IdentitySourceResponse, error) {
	identitySource, err := s.service.CreateIdentitySource(&azmodelsaap.IdentitySource{ApplicationID: identitySourceRequest.ApplicationID, Name: identitySourceRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource)
}

// UpdateIdentitySource updates an identity source.
func (s *V1AAPServer) UpdateIdentitySource(ctx context.Context, identitySourceRequest *IdentitySourceUpdateRequest) (*IdentitySourceResponse, error) {
	identitySource, err := s.service.UpdateIdentitySource((&azmodelsaap.IdentitySource{IdentitySourceID: identitySourceRequest.IdentitySourceID, ApplicationID: identitySourceRequest.ApplicationID, Name: identitySourceRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource)
}

// DeleteIdentitySource deletes an identity source.
func (s *V1AAPServer) DeleteIdentitySource(ctx context.Context, identitySourceRequest *IdentitySourceDeleteRequest) (*IdentitySourceResponse, error) {
	identitySource, err := s.service.DeleteIdentitySource(identitySourceRequest.ApplicationID, identitySourceRequest.IdentitySourceID)
	if err != nil {
		return nil, err
	}
	return MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource)
}

// FetchIdentitySources returns all identity sources.
func (s *V1AAPServer) FetchIdentitySources(identitySourceRequest *IdentitySourceFetchRequest, stream grpc.ServerStreamingServer[IdentitySourceResponse]) error {
	fields := map[string]any{}
	fields[azmodelsaap.FieldIdentitySourceApplicationID] = identitySourceRequest.ApplicationID
	if identitySourceRequest.Name != nil {
		fields[azmodelsaap.FieldIdentitySourceName] = *identitySourceRequest.Name
	}
	if identitySourceRequest.IdentitySourceID != nil {
		fields[azmodelsaap.FieldIdentitySourceIdentitySourceID] = *identitySourceRequest.IdentitySourceID
	}
	page := int32(0)
	if identitySourceRequest.Page != nil {
		page = int32(*identitySourceRequest.Page)
	}
	pageSize := int32(0)
	if identitySourceRequest.PageSize != nil {
		pageSize = int32(*identitySourceRequest.PageSize)
	}
	identitySources, err := s.service.FetchIdentitySources(page, pageSize, identitySourceRequest.ApplicationID, fields)
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
func (s *V1AAPServer) CreateIdentity(ctx context.Context, identityRequest *IdentityCreateRequest) (*IdentityResponse, error) {
	identity, err := s.service.CreateIdentity(&azmodelsaap.Identity{ApplicationID: identityRequest.ApplicationID, IdentitySourceID: identityRequest.IdentitySourceID, Kind: identityRequest.Kind, Name: identityRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentIdentityToGrpcIdentityResponse(identity)
}

// UpdateIdentity updates an identity.
func (s *V1AAPServer) UpdateIdentity(ctx context.Context, identityRequest *IdentityUpdateRequest) (*IdentityResponse, error) {
	identity, err := s.service.UpdateIdentity((&azmodelsaap.Identity{IdentityID: identityRequest.IdentityID, ApplicationID: identityRequest.ApplicationID, Kind: identityRequest.Kind, Name: identityRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentIdentityToGrpcIdentityResponse(identity)
}

// DeleteIdentity deletes an identity.
func (s *V1AAPServer) DeleteIdentity(ctx context.Context, identityRequest *IdentityDeleteRequest) (*IdentityResponse, error) {
	identity, err := s.service.DeleteIdentity(identityRequest.ApplicationID, identityRequest.IdentityID)
	if err != nil {
		return nil, err
	}
	return MapAgentIdentityToGrpcIdentityResponse(identity)
}

// FetchIdentities returns all identities.
func (s *V1AAPServer) FetchIdentities(identityRequest *IdentityFetchRequest, stream grpc.ServerStreamingServer[IdentityResponse]) error {
	fields := map[string]any{}
	fields[azmodelsaap.FieldIdentityApplicationID] = identityRequest.ApplicationID
	if identityRequest.IdentitySourceID != nil {
		fields[azmodelsaap.FieldIdentityIdentitySourceID] = *identityRequest.IdentitySourceID
	}
	if identityRequest.IdentityID != nil {
		fields[azmodelsaap.FieldIdentityIdentityID] = *identityRequest.IdentityID
	}
	if identityRequest.Kind != nil {
		fields[azmodelsaap.FieldIdentityKind] = *identityRequest.Kind
	}
	if identityRequest.Name != nil {
		fields[azmodelsaap.FieldIdentityName] = *identityRequest.Name
	}
	page := int32(0)
	if identityRequest.Page != nil {
		page = int32(*identityRequest.Page)
	}
	pageSize := int32(0)
	if identityRequest.PageSize != nil {
		pageSize = int32(*identityRequest.PageSize)
	}
	identities, err := s.service.FetchIdentities(page, pageSize, identityRequest.ApplicationID, fields)
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
func (s *V1AAPServer) CreateTenant(ctx context.Context, tenantRequest *TenantCreateRequest) (*TenantResponse, error) {
	tenant, err := s.service.CreateTenant(&azmodelsaap.Tenant{ApplicationID: tenantRequest.ApplicationID, Name: tenantRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentTenantToGrpcTenantResponse(tenant)
}

// UpdateTenant updates a tenant.
func (s *V1AAPServer) UpdateTenant(ctx context.Context, tenantRequest *TenantUpdateRequest) (*TenantResponse, error) {
	tenant, err := s.service.UpdateTenant((&azmodelsaap.Tenant{TenantID: tenantRequest.TenantID, ApplicationID: tenantRequest.ApplicationID, Name: tenantRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentTenantToGrpcTenantResponse(tenant)
}

// DeleteTenant deletes a tenant.
func (s *V1AAPServer) DeleteTenant(ctx context.Context, tenantRequest *TenantDeleteRequest) (*TenantResponse, error) {
	tenant, err := s.service.DeleteTenant(tenantRequest.ApplicationID, tenantRequest.TenantID)
	if err != nil {
		return nil, err
	}
	return MapAgentTenantToGrpcTenantResponse(tenant)
}

// FetchTenants returns all tenants.
func (s *V1AAPServer) FetchTenants(tenantRequest *TenantFetchRequest, stream grpc.ServerStreamingServer[TenantResponse]) error {
	fields := map[string]any{}
	fields[azmodelsaap.FieldTenantApplicationID] = tenantRequest.ApplicationID
	if tenantRequest.Name != nil {
		fields[azmodelsaap.FieldTenantName] = *tenantRequest.Name
	}
	if tenantRequest.TenantID != nil {
		fields[azmodelsaap.FieldTenantTenantID] = *tenantRequest.TenantID
	}
	page := int32(0)
	if tenantRequest.Page != nil {
		page = int32(*tenantRequest.Page)
	}
	pageSize := int32(0)
	if tenantRequest.PageSize != nil {
		pageSize = int32(*tenantRequest.PageSize)
	}
	tenants, err := s.service.FetchTenants(page, pageSize, tenantRequest.ApplicationID, fields)
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
