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

// CreateIdentity creates a new identity.
func (c *GrpcZAPClient) CreateIdentity(zoneID int64, identitySourceID string, kind string, name string) (*azmodelzap.Identity, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identity, err := client.CreateIdentity(context.Background(), &azapiv1zap.IdentityCreateRequest{ZoneID: zoneID, Kind: kind, Name: name, IdentitySourceID: identitySourceID})
	if err != nil {
		return nil, err
	}
	return azapiv1zap.MapGrpcIdentityResponseToAgentIdentity(identity)
}

// UpdateIdentity updates an identity.
func (c *GrpcZAPClient) UpdateIdentity(identity *azmodelzap.Identity) (*azmodelzap.Identity, error) {
	if identity == nil {
		azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientGeneric, "invalid identity instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedIdentity, err := client.UpdateIdentity(context.Background(), &azapiv1zap.IdentityUpdateRequest{
		IdentityID: identity.IdentityID,
		ZoneID:     identity.ZoneID,
		Kind:       identity.Kind,
		Name:       identity.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1zap.MapGrpcIdentityResponseToAgentIdentity(updatedIdentity)
}

// DeleteIdentity deletes an identity.
func (c *GrpcZAPClient) DeleteIdentity(zoneID int64, identityID string) (*azmodelzap.Identity, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identity, err := client.DeleteIdentity(context.Background(), &azapiv1zap.IdentityDeleteRequest{ZoneID: zoneID, IdentityID: identityID})
	if err != nil {
		return nil, err
	}
	return azapiv1zap.MapGrpcIdentityResponseToAgentIdentity(identity)
}

// FetchIdentities returns all identities.
func (c *GrpcZAPClient) FetchIdentities(page int32, pageSize int32, zoneID int64) ([]azmodelzap.Identity, error) {
	return c.FetchIdentitiesBy(page, pageSize, zoneID, "", "", "", "")
}

// FetchIdentitiesByID returns all identities filtering by identity id.
func (c *GrpcZAPClient) FetchIdentitiesByID(page int32, pageSize int32, zoneID int64, identityID string) ([]azmodelzap.Identity, error) {
	return c.FetchIdentitiesBy(page, pageSize, zoneID, "", identityID, "", "")
}

// FetchIdentitiesByEmail returns all identities filtering by name.
func (c *GrpcZAPClient) FetchIdentitiesByEmail(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.Identity, error) {
	return c.FetchIdentitiesBy(page, pageSize, zoneID, "", "", "", name)
}

// FetchIdentitiesBy returns all identities filtering by all criteria.
func (c *GrpcZAPClient) FetchIdentitiesBy(page int32, pageSize int32, zoneID int64, identitySourceID string, identityID string, kind string, name string) ([]azmodelzap.Identity, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identityFetchRequest := &azapiv1zap.IdentityFetchRequest{}
	identityFetchRequest.Page = &page
	identityFetchRequest.PageSize = &pageSize
	if zoneID > 0 {
		identityFetchRequest.ZoneID = zoneID
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
	identities := []azmodelzap.Identity{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		identity, err := azapiv1zap.MapGrpcIdentityResponseToAgentIdentity(response)
		if err != nil {
			return nil, err
		}
		identities = append(identities, *identity)
	}
	return identities, nil
}
