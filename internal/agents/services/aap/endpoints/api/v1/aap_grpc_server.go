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

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	grpc "google.golang.org/grpc"
)

// AAPService is the service for the AAP.
type AAPService interface {
	Setup() error

	// CreateAccount creates a new account.
	CreateAccount(account *azmodels.Account) (*azmodels.Account, error)
	// UpdateAccount updates an account.
	UpdateAccount(account *azmodels.Account) (*azmodels.Account, error)
	// DeleteAccount deletes an account.
	DeleteAccount(accountID int64) (*azmodels.Account, error)
	// FetchAccounts returns all the accounts.
	FetchAccounts(page int32, pageSize int32, filter map[string]any) ([]azmodels.Account, error)

	// CreateIdentitySource creates a new identity source.
	CreateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error)
	// UpdateIdentitySource updates an identity source.
	UpdateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(accountID int64, identitySourceID string) (*azmodels.IdentitySource, error)
	// FetchIdentitySources returns all the identity sources.
	FetchIdentitySources(page int32, pageSize int32, accountID int64, fields map[string]any) ([]azmodels.IdentitySource, error)

	// CreateIdentity creates a new identity.
	CreateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error)
	// UpdateIdentity updates an identity.
	UpdateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(accountID int64, identityID string) (*azmodels.Identity, error)
	// FetchIdentities returns all the identities.
	FetchIdentities(page int32, pageSize int32, accountID int64, fields map[string]any) ([]azmodels.Identity, error)

	// CreateTenant creates a new tenant.
	CreateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error)
	// UpdateTenant updates a tenant.
	UpdateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(accountID int64, tenantID string) (*azmodels.Tenant, error)
	// FetchTenants returns all the tenants.
	FetchTenants(page int32, pageSize int32, accountID int64, fields map[string]any) ([]azmodels.Tenant, error)
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

// CreateAccount creates a new account.
func (s *V1AAPServer) CreateAccount(ctx context.Context, accountRequest *AccountCreateRequest) (*AccountResponse, error) {
	account, err := s.service.CreateAccount(&azmodels.Account{Name: accountRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentAccountToGrpcAccountResponse(account)
}

// UpdateAccount updates an account.
func (s *V1AAPServer) UpdateAccount(ctx context.Context, accountRequest *AccountUpdateRequest) (*AccountResponse, error) {
	account, err := s.service.UpdateAccount((&azmodels.Account{AccountID: accountRequest.AccountID, Name: accountRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentAccountToGrpcAccountResponse(account)
}

// DeleteAccount deletes an account.
func (s *V1AAPServer) DeleteAccount(ctx context.Context, accountRequest *AccountDeleteRequest) (*AccountResponse, error) {
	account, err := s.service.DeleteAccount(accountRequest.AccountID)
	if err != nil {
		return nil, err
	}
	return MapAgentAccountToGrpcAccountResponse(account)
}

// FetchAccounts returns all the accounts.
func (s *V1AAPServer) FetchAccounts(accountRequest *AccountFetchRequest, stream grpc.ServerStreamingServer[AccountResponse]) error {
	fields := map[string]any{}
	if accountRequest.AccountID != nil {
		fields[azmodels.FieldAccountAccountID] = *accountRequest.AccountID
	}
	if accountRequest.Name != nil {
		fields[azmodels.FieldAccountName] = *accountRequest.Name

	}
	page := int32(0)
	if accountRequest.Page != nil {
		page = int32(*accountRequest.Page)
	}
	pageSize := int32(0)
	if accountRequest.PageSize != nil {
		pageSize = int32(*accountRequest.PageSize)
	}
	accounts, err := s.service.FetchAccounts(page, pageSize, fields)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		cvtedAccount, err := MapAgentAccountToGrpcAccountResponse(&account)
		if err != nil {
			return err
		}
		stream.SendMsg(cvtedAccount)
	}
	return nil
}

// CreateIdentitySource creates a new identity source.
func (s *V1AAPServer) CreateIdentitySource(ctx context.Context, identitySourceRequest *IdentitySourceCreateRequest) (*IdentitySourceResponse, error) {
	identitySource, err := s.service.CreateIdentitySource(&azmodels.IdentitySource{AccountID: identitySourceRequest.AccountID, Name: identitySourceRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource)
}

// UpdateIdentitySource updates an identity source.
func (s *V1AAPServer) UpdateIdentitySource(ctx context.Context, identitySourceRequest *IdentitySourceUpdateRequest) (*IdentitySourceResponse, error) {
	identitySource, err := s.service.UpdateIdentitySource((&azmodels.IdentitySource{IdentitySourceID: identitySourceRequest.IdentitySourceID, AccountID: identitySourceRequest.AccountID, Name: identitySourceRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource)
}

// DeleteIdentitySource deletes an identity source.
func (s *V1AAPServer) DeleteIdentitySource(ctx context.Context, identitySourceRequest *IdentitySourceDeleteRequest) (*IdentitySourceResponse, error) {
	identitySource, err := s.service.DeleteIdentitySource(identitySourceRequest.AccountID, identitySourceRequest.IdentitySourceID)
	if err != nil {
		return nil, err
	}
	return MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource)
}

// FetchIdentitySources returns all the identity sources.
func (s *V1AAPServer) FetchIdentitySources(ctx context.Context, identitySourceRequest *IdentitySourceFetchRequest) (*IdentitySourceListResponse, error) {
	fields := map[string]any{}
	fields[azmodels.FieldIdentitySourceAccountID] = identitySourceRequest.AccountID
	if identitySourceRequest.Name != nil {
		fields[azmodels.FieldIdentitySourceName] = *identitySourceRequest.Name
	}
	if identitySourceRequest.IdentitySourceID != nil {
		fields[azmodels.FieldIdentitySourceIdentitySourceID] = *identitySourceRequest.IdentitySourceID
	}
	page := int32(0)
	if identitySourceRequest.Page != nil {
		page = int32(*identitySourceRequest.Page)
	}
	pageSize := int32(0)
	if identitySourceRequest.PageSize != nil {
		pageSize = int32(*identitySourceRequest.PageSize)
	}
	identitySources, err := s.service.FetchIdentitySources(page, pageSize, identitySourceRequest.AccountID, fields)
	if err != nil {
		return nil, err
	}
	identitySourceList := &IdentitySourceListResponse{
		IdentitySources: make([]*IdentitySourceResponse, len(identitySources)),
	}
	for i, identitySource := range identitySources {
		cvtedIdentitySource, err := MapAgentIdentitySourceToGrpcIdentitySourceResponse(&identitySource)
		if err != nil {
			return nil, err
		}
		identitySourceList.IdentitySources[i] = cvtedIdentitySource
	}
	return identitySourceList, nil
}

// CreateIdentity creates a new identity.
func (s *V1AAPServer) CreateIdentity(ctx context.Context, identityRequest *IdentityCreateRequest) (*IdentityResponse, error) {
	identity, err := s.service.CreateIdentity(&azmodels.Identity{AccountID: identityRequest.AccountID, IdentitySourceID: identityRequest.IdentitySourceID, Kind: identityRequest.Kind, Name: identityRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentIdentityToGrpcIdentityResponse(identity)
}

// UpdateIdentity updates an identity.
func (s *V1AAPServer) UpdateIdentity(ctx context.Context, identityRequest *IdentityUpdateRequest) (*IdentityResponse, error) {
	identity, err := s.service.UpdateIdentity((&azmodels.Identity{IdentityID: identityRequest.IdentityID, AccountID: identityRequest.AccountID, Kind: identityRequest.Kind, Name: identityRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentIdentityToGrpcIdentityResponse(identity)
}

// DeleteIdentity deletes an identity.
func (s *V1AAPServer) DeleteIdentity(ctx context.Context, identityRequest *IdentityDeleteRequest) (*IdentityResponse, error) {
	identity, err := s.service.DeleteIdentity(identityRequest.AccountID, identityRequest.IdentityID)
	if err != nil {
		return nil, err
	}
	return MapAgentIdentityToGrpcIdentityResponse(identity)
}

// FetchIdentities returns all the identities.
func (s *V1AAPServer) FetchIdentities(ctx context.Context, identityRequest *IdentityFetchRequest) (*IdentityListResponse, error) {
	fields := map[string]any{}
	fields[azmodels.FieldIdentityAccountID] = identityRequest.AccountID
	if identityRequest.IdentitySourceID != nil {
		fields[azmodels.FieldIdentityIdentitySourceID] = *identityRequest.IdentitySourceID
	}
	if identityRequest.IdentityID != nil {
		fields[azmodels.FieldIdentityIdentityID] = *identityRequest.IdentityID
	}
	if identityRequest.Kind != nil {
		fields[azmodels.FieldIdentityKind] = *identityRequest.Kind
	}
	if identityRequest.Name != nil {
		fields[azmodels.FieldIdentityName] = *identityRequest.Name
	}
	page := int32(0)
	if identityRequest.Page != nil {
		page = int32(*identityRequest.Page)
	}
	pageSize := int32(0)
	if identityRequest.PageSize != nil {
		pageSize = int32(*identityRequest.PageSize)
	}
	identities, err := s.service.FetchIdentities(page, pageSize, identityRequest.AccountID, fields)
	if err != nil {
		return nil, err
	}
	identityList := &IdentityListResponse{
		Identities: make([]*IdentityResponse, len(identities)),
	}
	for i, identity := range identities {
		cvtedIdentity, err := MapAgentIdentityToGrpcIdentityResponse(&identity)
		if err != nil {
			return nil, err
		}
		identityList.Identities[i] = cvtedIdentity
	}
	return identityList, nil
}

// CreateTenant creates a new tenant.
func (s *V1AAPServer) CreateTenant(ctx context.Context, tenantRequest *TenantCreateRequest) (*TenantResponse, error) {
	tenant, err := s.service.CreateTenant(&azmodels.Tenant{AccountID: tenantRequest.AccountID, Name: tenantRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentTenantToGrpcTenantResponse(tenant)
}

// UpdateTenant updates a tenant.
func (s *V1AAPServer) UpdateTenant(ctx context.Context, tenantRequest *TenantUpdateRequest) (*TenantResponse, error) {
	tenant, err := s.service.UpdateTenant((&azmodels.Tenant{TenantID: tenantRequest.TenantID, AccountID: tenantRequest.AccountID, Name: tenantRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentTenantToGrpcTenantResponse(tenant)
}

// DeleteTenant deletes a tenant.
func (s *V1AAPServer) DeleteTenant(ctx context.Context, tenantRequest *TenantDeleteRequest) (*TenantResponse, error) {
	tenant, err := s.service.DeleteTenant(tenantRequest.AccountID, tenantRequest.TenantID)
	if err != nil {
		return nil, err
	}
	return MapAgentTenantToGrpcTenantResponse(tenant)
}

// FetchTenants returns all the tenants.
func (s *V1AAPServer) FetchTenants(ctx context.Context, tenantRequest *TenantFetchRequest) (*TenantListResponse, error) {
	fields := map[string]any{}
	fields[azmodels.FieldTenantAccountID] = tenantRequest.AccountID
	if tenantRequest.Name != nil {
		fields[azmodels.FieldTenantName] = *tenantRequest.Name
	}
	if tenantRequest.TenantID != nil {
		fields[azmodels.FieldTenantTenantID] = *tenantRequest.TenantID
	}
	page := int32(0)
	if tenantRequest.Page != nil {
		page = int32(*tenantRequest.Page)
	}
	pageSize := int32(0)
	if tenantRequest.PageSize != nil {
		pageSize = int32(*tenantRequest.PageSize)
	}
	tenants, err := s.service.FetchTenants(page, pageSize, tenantRequest.AccountID, fields)
	if err != nil {
		return nil, err
	}
	tenantList := &TenantListResponse{
		Tenants: make([]*TenantResponse, len(tenants)),
	}
	for i, tenant := range tenants {
		cvtedTenant, err := MapAgentTenantToGrpcTenantResponse(&tenant)
		if err != nil {
			return nil, err
		}
		tenantList.Tenants[i] = cvtedTenant
	}
	return tenantList, nil
}
