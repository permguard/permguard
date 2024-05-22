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

package grpcclients

import (
	"context"
	"errors"

	azapiv1aap "github.com/permguard/permguard/internal/agents/services/aap/endpoints/api/v1"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// CreateIdentity creates a new identity.
func (c *GrpcAAPClient) CreateIdentity(accountID int64, identitySourceID string, kind string, name string) (*azmodels.Identity, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identity, err := client.CreateIdentity(context.Background(), &azapiv1aap.IdentityCreateRequest{AccountID: accountID, Kind: kind, Name: name, IdentitySourceID: identitySourceID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentityResponseToAgentIdentity(identity)
}

// UpdateIdentity updates an identity.
func (c *GrpcAAPClient) UpdateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error) {
	if identity == nil {
		return nil, errors.New("client: invalid identity instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedIdentity, err := client.UpdateIdentity(context.Background(), &azapiv1aap.IdentityUpdateRequest{
		IdentityID: identity.IdentityID,
		AccountID:  identity.AccountID,
		Kind:       identity.Kind,
		Name:       identity.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentityResponseToAgentIdentity(updatedIdentity)
}

// DeleteIdentity deletes an identity.
func (c *GrpcAAPClient) DeleteIdentity(accountID int64, identityID string) (*azmodels.Identity, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identity, err := client.DeleteIdentity(context.Background(), &azapiv1aap.IdentityDeleteRequest{AccountID: accountID, IdentityID: identityID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentityResponseToAgentIdentity(identity)
}

// GetAllIdentities returns all the identities.
func (c *GrpcAAPClient) GetAllIdentities(accountID int64) ([]azmodels.Identity, error) {
	return c.GetIdentitiesBy(accountID, "", "", "", "")
}

// GetIdentitiesByID returns all identities filtering by identity id.
func (c *GrpcAAPClient) GetIdentitiesByID(accountID int64, identityID string) ([]azmodels.Identity, error) {
	return c.GetIdentitiesBy(accountID, "", identityID, "", "")
}

// GetIdentitiesByEmail returns all identities filtering by name.
func (c *GrpcAAPClient) GetIdentitiesByEmail(accountID int64, name string) ([]azmodels.Identity, error) {
	return c.GetIdentitiesBy(accountID, "", "", "", name)
}

// GetIdentitiesBy returns all identities filtering by all criteria.
func (c *GrpcAAPClient) GetIdentitiesBy(accountID int64, identitySourceID string, identityID string, kind string, name string) ([]azmodels.Identity, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identityGetRequest := &azapiv1aap.IdentityGetRequest{}
	if accountID > 0 {
		identityGetRequest.AccountID = accountID
	}
	if identitySourceID != "" {
		identityGetRequest.IdentitySourceID = &identitySourceID
	}
	if kind != "" {
		identityGetRequest.Kind = &kind
	}
	if name != "" {
		identityGetRequest.Name = &name
	}
	if identityID != "" {
		identityGetRequest.IdentityID = &identityID
	}
	identityList, err := client.GetAllIdentities(context.Background(), identityGetRequest)
	if err != nil {
		return nil, err
	}
	identities := make([]azmodels.Identity, len(identityList.Identities))
	for i, identity := range identityList.Identities {
		identity, err := azapiv1aap.MapGrpcIdentityResponseToAgentIdentity(identity)
		if err != nil {
			return nil, err
		}
		identities[i] = *identity
	}
	return identities, nil
}
