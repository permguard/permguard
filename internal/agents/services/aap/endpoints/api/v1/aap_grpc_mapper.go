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

	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// MapPointerStringToString maps a pointer string to a string.
func MapPointerStringToString(str *string) string {
	response := ""
	if str != nil {
		response = *str
	}
	return response
}

// MapGrpcAccountResponseToAgentAccount maps the gRPC account to the agent account.
func MapGrpcAccountResponseToAgentAccount(account *AccountResponse) (*azmodels.Account, error) {
	return &azmodels.Account{
		AccountID: account.AccountID,
		CreatedAt: account.CreatedAt.AsTime(),
		UpdatedAt: account.UpdatedAt.AsTime(),
		Name:      account.Name,
	}, nil
}

// MapAgentAccountToGrpcAccountResponse maps the agent account to the gRPC account.
func MapAgentAccountToGrpcAccountResponse(account *azmodels.Account) (*AccountResponse, error) {
	return &AccountResponse{
		AccountID: account.AccountID,
		CreatedAt: timestamppb.New(account.CreatedAt),
		UpdatedAt: timestamppb.New(account.UpdatedAt),
		Name:      account.Name,
	}, nil
}

// MapGrpcTenantResponseToAgentTenant maps the gRPC tenant to the agent tenant.
func MapGrpcTenantResponseToAgentTenant(tenant *TenantResponse) (*azmodels.Tenant, error) {
	return &azmodels.Tenant{
		TenantID:  tenant.TenantID,
		CreatedAt: tenant.CreatedAt.AsTime(),
		UpdatedAt: tenant.UpdatedAt.AsTime(),
		AccountID: tenant.AccountID,
		Name:      tenant.Name,
	}, nil
}

// MapAgentTenantToGrpcTenantResponse maps the agent tenant to the gRPC tenant.
func MapAgentTenantToGrpcTenantResponse(tenant *azmodels.Tenant) (*TenantResponse, error) {
	return &TenantResponse{
		TenantID:  tenant.TenantID,
		CreatedAt: timestamppb.New(tenant.CreatedAt),
		UpdatedAt: timestamppb.New(tenant.UpdatedAt),
		AccountID: tenant.AccountID,
		Name:      tenant.Name,
	}, nil
}

// MapGrpcIdentitySourceResponseToAgentIdentitySource maps the gRPC identity source to the agent identity source.
func MapGrpcIdentitySourceResponseToAgentIdentitySource(identitySource *IdentitySourceResponse) (*azmodels.IdentitySource, error) {
	return &azmodels.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		CreatedAt:        identitySource.CreatedAt.AsTime(),
		UpdatedAt:        identitySource.UpdatedAt.AsTime(),
		AccountID:        identitySource.AccountID,
		Name:             identitySource.Name,
	}, nil
}

// MapAgentIdentitySourceToGrpcIdentitySourceResponse maps the agent identity source to the gRPC identity source.
func MapAgentIdentitySourceToGrpcIdentitySourceResponse(identitySource *azmodels.IdentitySource) (*IdentitySourceResponse, error) {
	return &IdentitySourceResponse{
		IdentitySourceID: identitySource.IdentitySourceID,
		CreatedAt:        timestamppb.New(identitySource.CreatedAt),
		UpdatedAt:        timestamppb.New(identitySource.UpdatedAt),
		AccountID:        identitySource.AccountID,
		Name:             identitySource.Name,
	}, nil
}

// MapGrpcIdentityResponseToAgentIdentity maps the gRPC identity to the agent identity.
func MapGrpcIdentityResponseToAgentIdentity(identity *IdentityResponse) (*azmodels.Identity, error) {
	return &azmodels.Identity{
		IdentityID:       identity.IdentityID,
		CreatedAt:        identity.CreatedAt.AsTime(),
		UpdatedAt:        identity.UpdatedAt.AsTime(),
		AccountID:        identity.AccountID,
		IdentitySourceID: identity.IdentitySourceID,
		Kind:             identity.Kind,
		Name:             identity.Name,
	}, nil
}

// MapAgentIdentityToGrpcIdentityResponse maps the agent identity to the gRPC identity.
func MapAgentIdentityToGrpcIdentityResponse(identity *azmodels.Identity) (*IdentityResponse, error) {
	return &IdentityResponse{
		IdentityID:       identity.IdentityID,
		CreatedAt:        timestamppb.New(identity.CreatedAt),
		UpdatedAt:        timestamppb.New(identity.UpdatedAt),
		AccountID:        identity.AccountID,
		IdentitySourceID: identity.IdentitySourceID,
		Kind:             identity.Kind,
		Name:             identity.Name,
	}, nil
}
