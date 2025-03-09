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

// CreateIdentitySource creates a new identity source.
func (c *GrpcZAPClient) CreateIdentitySource(zoneID int64, name string) (*azmodelzap.IdentitySource, error) {
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	identitySource, err := client.CreateIdentitySource(context.Background(), &azapiv1zap.IdentitySourceCreateRequest{ZoneID: zoneID, Name: name})
	if err != nil {
		return nil, err
	}
	return azapiv1zap.MapGrpcIdentitySourceResponseToAgentIdentitySource(identitySource)
}

// UpdateIdentitySource updates an identity source.
func (c *GrpcZAPClient) UpdateIdentitySource(identitySource *azmodelzap.IdentitySource) (*azmodelzap.IdentitySource, error) {
	if identitySource == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientGeneric, "invalid identity source instance")
	}
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	updatedIdentitySource, err := client.UpdateIdentitySource(context.Background(), &azapiv1zap.IdentitySourceUpdateRequest{
		IdentitySourceID: identitySource.IdentitySourceID,
		ZoneID:           identitySource.ZoneID,
		Name:             identitySource.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1zap.MapGrpcIdentitySourceResponseToAgentIdentitySource(updatedIdentitySource)
}

// DeleteIdentitySource deletes an identity source.
func (c *GrpcZAPClient) DeleteIdentitySource(zoneID int64, identitySourceID string) (*azmodelzap.IdentitySource, error) {
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	identitySource, err := client.DeleteIdentitySource(context.Background(), &azapiv1zap.IdentitySourceDeleteRequest{ZoneID: zoneID, IdentitySourceID: identitySourceID})
	if err != nil {
		return nil, err
	}
	return azapiv1zap.MapGrpcIdentitySourceResponseToAgentIdentitySource(identitySource)
}

// FetchIdentitySources returns all identity sources.
func (c *GrpcZAPClient) FetchIdentitySources(page int32, pageSize int32, zoneID int64) ([]azmodelzap.IdentitySource, error) {
	return c.FetchIdentitySourcesBy(page, pageSize, zoneID, "", "")
}

// FetchIdentitySourcesByID returns all identity sources filtering by identity source id.
func (c *GrpcZAPClient) FetchIdentitySourcesByID(page int32, pageSize int32, zoneID int64, identitySourceID string) ([]azmodelzap.IdentitySource, error) {
	return c.FetchIdentitySourcesBy(page, pageSize, zoneID, identitySourceID, "")
}

// FetchIdentitySourcesByName returns all identity sources filtering by name.
func (c *GrpcZAPClient) FetchIdentitySourcesByName(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.IdentitySource, error) {
	return c.FetchIdentitySourcesBy(page, pageSize, zoneID, "", name)
}

// FetchIdentitySourcesBy returns all identity sources filtering by identity source id and name.
func (c *GrpcZAPClient) FetchIdentitySourcesBy(page int32, pageSize int32, zoneID int64, identitySourceID string, name string) ([]azmodelzap.IdentitySource, error) {
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	identitySourceFetchRequest := &azapiv1zap.IdentitySourceFetchRequest{}
	identitySourceFetchRequest.Page = &page
	identitySourceFetchRequest.PageSize = &pageSize
	if zoneID > 0 {
		identitySourceFetchRequest.ZoneID = zoneID
	}
	if name != "" {
		identitySourceFetchRequest.Name = &name
	}
	if identitySourceID != "" {
		identitySourceFetchRequest.IdentitySourceID = &identitySourceID
	}
	stream, err := client.FetchIdentitySources(context.Background(), identitySourceFetchRequest)
	if err != nil {
		return nil, err
	}
	identitySources := []azmodelzap.IdentitySource{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		identitySource, err := azapiv1zap.MapGrpcIdentitySourceResponseToAgentIdentitySource(response)
		if err != nil {
			return nil, err
		}
		identitySources = append(identitySources, *identitySource)
	}
	return identitySources, nil
}
