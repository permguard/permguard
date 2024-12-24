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

	azapiv1aap "github.com/permguard/permguard/internal/agents/services/aap/endpoints/api/v1"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// CreateIdentity creates a new identity.
func (c *GrpcAAPClient) CreateIdentity(applicationID int64, identitySourceID string, kind string, name string) (*azmodels.Identity, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identity, err := client.CreateIdentity(context.Background(), &azapiv1aap.IdentityCreateRequest{ApplicationID: applicationID, Kind: kind, Name: name, IdentitySourceID: identitySourceID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentityResponseToAgentIdentity(identity)
}

// UpdateIdentity updates an identity.
func (c *GrpcAAPClient) UpdateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error) {
	if identity == nil {
		azerrors.WrapSystemError(azerrors.ErrClientGeneric, "client: invalid identity instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedIdentity, err := client.UpdateIdentity(context.Background(), &azapiv1aap.IdentityUpdateRequest{
		IdentityID:    identity.IdentityID,
		ApplicationID: identity.ApplicationID,
		Kind:          identity.Kind,
		Name:          identity.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentityResponseToAgentIdentity(updatedIdentity)
}

// DeleteIdentity deletes an identity.
func (c *GrpcAAPClient) DeleteIdentity(applicationID int64, identityID string) (*azmodels.Identity, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identity, err := client.DeleteIdentity(context.Background(), &azapiv1aap.IdentityDeleteRequest{ApplicationID: applicationID, IdentityID: identityID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentityResponseToAgentIdentity(identity)
}

// FetchIdentities returns all identities.
func (c *GrpcAAPClient) FetchIdentities(page int32, pageSize int32, applicationID int64) ([]azmodels.Identity, error) {
	return c.FetchIdentitiesBy(page, pageSize, applicationID, "", "", "", "")
}

// FetchIdentitiesByID returns all identities filtering by identity id.
func (c *GrpcAAPClient) FetchIdentitiesByID(page int32, pageSize int32, applicationID int64, identityID string) ([]azmodels.Identity, error) {
	return c.FetchIdentitiesBy(page, pageSize, applicationID, "", identityID, "", "")
}

// FetchIdentitiesByEmail returns all identities filtering by name.
func (c *GrpcAAPClient) FetchIdentitiesByEmail(page int32, pageSize int32, applicationID int64, name string) ([]azmodels.Identity, error) {
	return c.FetchIdentitiesBy(page, pageSize, applicationID, "", "", "", name)
}

// FetchIdentitiesBy returns all identities filtering by all criteria.
func (c *GrpcAAPClient) FetchIdentitiesBy(page int32, pageSize int32, applicationID int64, identitySourceID string, identityID string, kind string, name string) ([]azmodels.Identity, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identityFetchRequest := &azapiv1aap.IdentityFetchRequest{}
	identityFetchRequest.Page = &page
	identityFetchRequest.PageSize = &pageSize
	if applicationID > 0 {
		identityFetchRequest.ApplicationID = applicationID
	}
	if identitySourceID != "" {
		identityFetchRequest.IdentitySourceID = &identitySourceID
	}
	if kind != "" {
		identityFetchRequest.Kind = &kind
	}
	if name != "" {
		identityFetchRequest.Name = &name
	}
	if identityID != "" {
		identityFetchRequest.IdentityID = &identityID
	}
	stream, err := client.FetchIdentities(context.Background(), identityFetchRequest)
	if err != nil {
		return nil, err
	}
	identities := []azmodels.Identity{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		identity, err := azapiv1aap.MapGrpcIdentityResponseToAgentIdentity(response)
		if err != nil {
			return nil, err
		}
		identities = append(identities, *identity)
	}
	return identities, nil
}
